package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.PersistentTaskExecutor;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.Message;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

public class Peer {
	// Logger
	private static final Logger logger = System.getLogger(Peer.class.getName());

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
		logger.log(DEBUG, "Created peer {0}", this);
	}

	public void start() throws IOException {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		executeWorkers();
	}

	private void executeWorkers() throws IOException {
		try (var executor = new PersistentTaskExecutor<>(toString(), IOException::new, logger)) {
			executor.submit("Keepalive worker", keepaliveWorker::run);
			executor.submit("Decryption worker", decryptionWorker::run);
			executor.submit("Session worker", sessionManager::run);

			executor.join();
			executor.throwIfFailed();
		} catch (InterruptedException e) {
			logger.log(INFO, "Peer {0} interrupted", this);
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
			default -> logger.log(WARNING, "Received unexpected message type: {0}", message);
		}
	}

	public int sessionIndex() {
		return sessionManager.tryGetSessionNow().localIndex();
	}

	@Override
	public String toString() {
		return String.format("Peer{%s, pubkey %s}", getAuthority(), remoteStatic.toString().substring(0, 8));
	}

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

	public int writeTransportPacket(ByteBuffer data) throws InterruptedException, IOException {
		return sessionManager.waitForSession().writeTransportPacket(data);
	}

	public NoisePresharedKey getPresharedKey() {
		return presharedKey;
	}

	record TransportWithSession(MessageTransport transport, EstablishedSession session) {
	}
}
