package ax.xz.wireguard;

import ax.xz.wireguard.crypto.NoisePresharedKey;
import ax.xz.wireguard.crypto.NoisePublicKey;
import org.slf4j.Logger;

import javax.management.*;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

public class Peer implements PeerMBean {
	public static final ScopedValue<Peer> CURRENT_PEER = ScopedValue.newInstance();

	static {
		ScopedLogger.addScopedMarker("peer", CURRENT_PEER);
	}

	// Logger
	private static final Logger logger = ScopedLogger.getLogger(Peer.class);

	// Instance variables
	private final WireguardDevice device;
	private final NoisePublicKey remoteStatic;
	private final NoisePresharedKey presharedKey;

	private final KeepaliveWorker keepaliveWorker;
	private final DecryptionWorker decryptionWorker;
	private final SessionManager sessionManager;

	private final AtomicBoolean started = new AtomicBoolean(false);

	Peer(WireguardDevice device, SocketAddress endpoint, NoisePublicKey remoteStatic, NoisePresharedKey presharedKey, Duration keepaliveInterval) {
		this.device = device;
		this.remoteStatic = remoteStatic;

		this.sessionManager = new SessionManager(this, device, endpoint);
		this.presharedKey = presharedKey;
		this.decryptionWorker = new DecryptionWorker(sessionManager);
		this.keepaliveWorker = new KeepaliveWorker(sessionManager, keepaliveInterval);

		logger.debug("Created peer {}", this);
		registerPeerMBean();
	}

	public void start() throws IOException, InterruptedException {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		try {
			ScopedValue.runWhere(CURRENT_PEER, this, this::executeWorkers);
		} finally {
			unregisterPeerMBean();
		}
	}

	private void executeWorkers() {
		try (var executor = new WorkerThreadScope()) {
			executor.fork(keepaliveWorker);
			executor.fork(decryptionWorker);
			executor.fork(sessionManager);

			executor.join();
		} catch (InterruptedException e) {
			logger.info("Peer {} interrupted", this);
		} catch (Exception e) {
			logger.error("Peer {} failed", this, e);
		}
	}

	/**
	 * Removes a decrypted transport message from the queue, and waits if none is present
	 *
	 * @return decrypted transport packet received
	 * @throws InterruptedException if the thread is interrupted whilst waiting
	 */
	public ByteBuffer readTransportPacket() throws InterruptedException {
		return decryptionWorker.receiveDecryptedTransport();
	}

	public NoisePublicKey getRemoteStatic() {
		return remoteStatic;
	}

	void receiveInboundMessage(SocketAddress address, Message message) {
		switch (message) {
			case MessageTransport transport -> decryptionWorker.receiveTransport(transport);
			case MessageInitiation initiation -> sessionManager.receiveInitiation(address, initiation);
			case MessageResponse response -> sessionManager.receiveHandshakeResponse(address, response);
			default -> logger.warn("Received unexpected message type: {}", message);
		}
	}

	public int sessionIndex() {
		return sessionManager.tryGetSessionNow().localIndex();
	}

	@Override
	public int getInboundQueueSize() {
		return decryptionWorker.getInboundTransportQueueSize();
	}

	@Override
	public int getDecryptedQueueSize() {
		return decryptionWorker.getDecryptedTransportQueueSize();
	}

	@Override
	public String toString() {
		return String.format("Peer{%s, pubkey %s}", getAuthority(), remoteStatic.toString().substring(0, 8));
	}

	@Override
	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			if (sessionManager.hasEndpoint())
				return ((InetSocketAddress) sessionManager.getEndpoint()).toString();
			else
				return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	public ObjectName getObjectName() {
		try {
			return new ObjectName("ax.xz.wireguard:type=Peer,device=" + device + ",publicKey=" + remoteStatic.toString().substring(0, 8));
		} catch (MalformedObjectNameException e) {
			throw new Error(e);
		}
	}

	public int writeTransportPacket(ByteBuffer data) throws InterruptedException, IOException {
		return sessionManager.waitForSession().writeTransportPacket(data);
	}

	public NoisePresharedKey getPresharedKey() {
		return presharedKey;
	}

	private void registerPeerMBean() {
		try {
			ManagementFactory.getPlatformMBeanServer().registerMBean(this, getObjectName());
		} catch (NotCompliantMBeanException | InstanceAlreadyExistsException e) {
			throw new Error(e);
		} catch (MBeanRegistrationException e) {
			logger.warn("Unable to register peer MBean", e);
		}
	}

	private void unregisterPeerMBean() {
		try {
			ManagementFactory.getPlatformMBeanServer().unregisterMBean(getObjectName());
		} catch (InstanceNotFoundException | MBeanRegistrationException e) {
			logger.warn("Unable to unregister peer MBean", e);
		}
	}

	record TransportWithSession(MessageTransport transport, EstablishedSession session) {
	}
}
