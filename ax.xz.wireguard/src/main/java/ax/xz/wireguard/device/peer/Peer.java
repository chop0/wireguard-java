package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.crypto.keys.NoisePresharedKey;
import ax.xz.wireguard.crypto.keys.NoisePublicKey;
import ax.xz.wireguard.device.PersistentTaskExecutor;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.message.Message;
import ax.xz.wireguard.message.MessageInitiation;
import ax.xz.wireguard.message.MessageResponse;
import ax.xz.wireguard.message.MessageTransport;
import ax.xz.wireguard.util.ScopedLogger;
import org.slf4j.Logger;

import javax.management.*;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.atomic.AtomicBoolean;

public class Peer implements PeerMBean {
	public static final ScopedValue<Peer> CURRENT_PEER = ScopedValue.newInstance();

	static {
		ScopedLogger.addScopedMarker("peer", CURRENT_PEER);
	}

	// Logger
	private static final Logger logger = ScopedLogger.getLogger(Peer.class);

	// Instance variables
	private final NoisePublicKey remoteStatic;
	private final NoisePresharedKey presharedKey;

	private final KeepaliveWorker keepaliveWorker;
	private final DecryptionWorker decryptionWorker;
	private final SessionManager sessionManager;

	private final AtomicBoolean started = new AtomicBoolean(false);

	public Peer(WireguardDevice device, InetSocketAddress endpoint, NoisePublicKey remoteStatic, NoisePresharedKey presharedKey, Duration keepaliveInterval) {
		this.remoteStatic = remoteStatic;

		this.sessionManager = new SessionManager(this, device, endpoint);
		this.presharedKey = presharedKey;
		this.decryptionWorker = new DecryptionWorker(sessionManager);
		this.keepaliveWorker = new KeepaliveWorker(sessionManager, keepaliveInterval);

		logger.debug("Created peer {}", this);
		registerPeerMBean();
	}

	public void start() throws IOException {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		try {
			executeWorkers();
		} finally {
			unregisterPeerMBean();
		}
	}

	private void executeWorkers() throws IOException {
		try (var executor = new PersistentTaskExecutor<>(IOException::new, logger)) {
			executor.submit("Keepalive worker", keepaliveWorker::run);
			executor.submit("Decryption worker", decryptionWorker::run);
			executor.submit("Session worker", sessionManager::run);

			executor.join();
			executor.throwIfFailed();
		} catch (InterruptedException e) {
			logger.info("Peer {} interrupted", this);
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

	public void receiveInboundMessage(InetSocketAddress address, Message message) {
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
			if (sessionManager.hasEndpoint()) {
				return sessionManager.getEndpoint().getHostString();
			}
			else
				return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	public ObjectName getObjectName() {
		try {
			return new ObjectName("ax.xz.wireguard:type=Peer" + ",publicKey=" + remoteStatic.toString().substring(0, 8));
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
