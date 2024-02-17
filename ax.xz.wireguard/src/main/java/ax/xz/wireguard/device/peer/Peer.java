package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.BufferPool;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.Message;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;
import ax.xz.wireguard.keys.NoisePresharedKey;
import ax.xz.wireguard.keys.NoisePublicKey;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.WARNING;
import static java.util.Objects.requireNonNull;

public class Peer {
	private static final Logger logger = System.getLogger(Peer.class.getName());

	// a queue of transport messages that have been decrypted and need to be sent up the stack
	private final LinkedBlockingQueue<BufferPool.BufferGuard> inboundTransportQueue;
	private final PeerConnectionInfo connectionInfo;
	private final WireguardDevice device;
	private final BufferPool bufferPool;

	private final SessionManager sessionManager;

	private final AtomicBoolean started = new AtomicBoolean(false);

	public Peer(WireguardDevice device, LinkedBlockingQueue<BufferPool.BufferGuard> inboundTransportQueue, PeerConnectionInfo connectionInfo, BufferPool bufferPool) {
		this.inboundTransportQueue = inboundTransportQueue;
		this.connectionInfo = connectionInfo;
		this.device = device;
		this.bufferPool = bufferPool;

		this.sessionManager = new SessionManager(this, device, connectionInfo);
	}

	public void start() {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		logger.log(DEBUG, "Started peer {0}", this);
		sessionManager.run();
	}

	public NoisePublicKey getRemoteStatic() {
		return connectionInfo.remoteStatic;
	}

	/**
	 * Processes an inbound message from the peer.
	 * Releases the buffer backing the message when done with it
	 * @param address the address the message was received from
	 * @param message the message to process.  must be allocated from the device's buffer pool
	 */
	public void receiveInboundMessage(InetSocketAddress address, Message message) {
		switch (message) {
			case MessageTransport transport -> receiveTransport(transport);
			case MessageInitiation initiation -> sessionManager.receiveInitiation(address, initiation);
			case MessageResponse response -> sessionManager.receiveHandshakeResponse(response);
			default -> logger.log(WARNING, "Received unexpected message type: {0}", message);
		}
	}

	private static final ExecutorService packetProcessor = ForkJoinPool.commonPool();

	/**
	 * Enqueues an inbound transport message to be processed.
	 * Releases the transport buffer when done with it
	 *
	 * @param transport the transport message to enqueue
	 */
	void receiveTransport(MessageTransport transport) {
		// no use waiting for a session, since if the session is not established, we will not be able to decrypt the message
		// because any sessions created in the future will have a different keypair
		var currentSession = sessionManager.tryGetSessionNow();
		if (currentSession == null) {
			transport.close();
			return;
		}

		packetProcessor.execute(() -> decryptAndEnqueue(transport, currentSession));
	}

	/**
	 * Sends the given transport data to the peer.
	 *
	 * @param data data to send
	 */
	public void enqueueTransportPacket(BufferPool.BufferGuard data) {
		packetProcessor.execute(() -> {
			try (data) {
				var session = sessionManager.tryGetSessionNow();
				if (session == null)
					return;

				var result = session.createTransportPacket(data.buffer());
				device.queueTransmit(session.getOutboundPacketAddress(), result.bufferGuard());
			}
		});
	}

	/**
	 * Decrypts a transport message and enqueues it for reading.  Releases the transport buffer when done with it
	 */
	private void decryptAndEnqueue(MessageTransport transport, EstablishedSession session) {
		try {
			if (transport.content().remaining() < 16) {
				logger.log(WARNING, "Received transport message with invalid length");
				return;
			}

			var result = bufferPool.acquire(transport.content().remaining() - 16);
			session.decryptTransportPacket(transport, result.buffer());
			result.buffer().flip();

			if (result.buffer().remaining() == 0) {
				logger.log(DEBUG, "Received keepalive");
				result.close();
			} else
				inboundTransportQueue.add(result);
		} catch (Throwable e) {
			logger.log(WARNING, "Error decrypting transport message", e);
		} finally {
			transport.close();
		}

	}

	@Override
	public String toString() {
		return String.format("Peer{%s, pubkey %s}", getAuthority(), connectionInfo.remoteStatic.toString().substring(0, 8));
	}

	@Override
	public int hashCode() {
		return connectionInfo.remoteStatic.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Peer peer) {
			return connectionInfo.remoteStatic.equals(peer.connectionInfo.remoteStatic);
		} else {
			return false;
		}
	}

	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	public record PeerConnectionInfo(NoisePublicKey remoteStatic, NoisePresharedKey presharedKey,
									 InetSocketAddress endpoint, Duration keepaliveInterval) {
		public PeerConnectionInfo {
			requireNonNull(remoteStatic);

			if (keepaliveInterval == null)
				keepaliveInterval = Duration.ofDays(1_000_000_000);

			if (presharedKey == null)
				presharedKey = NoisePresharedKey.zero();
		}

		@Override
		public String toString() {
			if (endpoint != null)
				return endpoint.toString();
			else
				return remoteStatic.toString().substring(0, 8);
		}
	}
}
