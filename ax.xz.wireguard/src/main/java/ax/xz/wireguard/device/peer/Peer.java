package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.Message;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.PersistentTaskExecutor;

import javax.annotation.Nullable;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;
import static java.util.Objects.requireNonNull;

public class Peer {
	public static final ScopedValue<Peer> PEER = ScopedValue.newInstance();

	private static final Logger logger = System.getLogger(Peer.class.getName());

	// a queue of transport messages that have been decrypted and need to be sent up the stack
	private final LinkedBlockingQueue<ByteBuffer> inboundTransportQueue;

	// a queue of outgoing transport message that are yet to be encrypted
	private final LinkedBlockingQueue<ByteBuffer> outboundEncryptionQueue = new LinkedBlockingQueue<>(1024);

	// a queue of inbound transport messages
	private final LinkedBlockingQueue<TransportWithSession> inboundDecryptionQueue = new LinkedBlockingQueue<>(1024);

	private final PeerConnectionInfo connectionInfo;

	private final SessionManager sessionManager;
	private final WireguardDevice device;

	private final AtomicBoolean started = new AtomicBoolean(false);

	public Peer(WireguardDevice device, LinkedBlockingQueue<ByteBuffer> inboundTransportQueue, PeerConnectionInfo connectionInfo) {
		this.inboundTransportQueue = inboundTransportQueue;
		this.connectionInfo = connectionInfo;
		this.device = device;

		this.sessionManager = new SessionManager(device, connectionInfo);
		logger.log(DEBUG, "Created peer {0}", this);
	}

	public void start() throws IOException {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		ScopedValue.runWhere(PEER, this, () -> {
			try (var sts = new PersistentTaskExecutor<>("Peer executor", Function.identity(), logger)) {
				sts.submit("Session manager", sessionManager::run);

				sts.join();
			} catch (InterruptedException e) {
				logger.log(DEBUG, "Peer interrupted");
			} finally {
				logger.log(DEBUG, "Peer shutting down");
			}
		});
	}

	public NoisePublicKey getRemoteStatic() {
		return connectionInfo.remoteStatic;
	}

	public void receiveInboundMessage(InetSocketAddress address, Message message) {
		switch (message) {
			case MessageTransport transport -> receiveTransport(transport);
			case MessageInitiation initiation -> sessionManager.receiveInitiation(address, initiation);
			case MessageResponse response -> sessionManager.receiveHandshakeResponse(response);
			default -> logger.log(WARNING, "Received unexpected message type: {0}", message);
		}
	}

	private final ExecutorService packetProcessor = Executors.newVirtualThreadPerTaskExecutor();

	/**
	 * Enqueues an inbound transport message to be processed
	 *
	 * @param transport the transport message to enqueue
	 */
	void receiveTransport(MessageTransport transport) {
		// no use waiting for a session, since if the session is not established, we will not be able to decrypt the message
		// because any sessions created in the future will have a different keypair
		var currentSession = sessionManager.tryGetSessionNow();
		if (currentSession == null)
			return;

		packetProcessor.execute(() -> decryptAndEnqueue(new Peer.TransportWithSession(transport, currentSession)));
	}

	/**
	 * Sends the given transport data to the peer.
	 *
	 * @param data data to send
	 * @throws IOException if no session is established or something is wrong with the socket
	 */
	public void enqueueTransportPacket(ByteBuffer data) {
		packetProcessor.execute(() -> encryptAndEnqueue(data));
	}

	/**
	 * Encrypts all transport messages in the given list and sends them to the peer
	 *
	 * @param message the messages to encrypt
	 */
	private void encryptAndEnqueue(ByteBuffer message) {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return;

		try {
			session.sendTransportPacket(device, message);
		} catch (IOException e) {
			logger.log(DEBUG, "Error sending transport packet", e);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * Decrypts a transport message and enqueues it for reading
	 *
	 * @param inb the transport message to decrypt
	 * @return true if the message was successfully decrypted, false otherwise
	 */
	private boolean decryptAndEnqueue(Peer.TransportWithSession inb) {
		int packetSize = inb.transport().content().remaining();
		try {
			if (inb.session() == null)
				return false;

			if (inb.transport().content().remaining() < 16) {
				logger.log(WARNING, "Received transport message with invalid length");
				return false;
			}

			var result = ByteBuffer.allocate(inb.transport().content().remaining() - 16);
			inb.session().decryptTransportPacket(inb.transport(), result);
			result.flip();

			if (result.remaining() == 0) {
				logger.log(DEBUG, "Received keepalive");
			} else
				inboundTransportQueue.add(result);

			return true;
		} catch (ShortBufferException e) {
			int minimumSize = (int) (packetSize * 1.5);

			if (device.receiveBufferSize() < minimumSize) {
				logger.log(INFO, "Growing receive buffer");
				device.setReceiveBufferSize((int) (packetSize * 1.5));
			}
		} catch (Throwable e) {
			logger.log(WARNING, "Error decrypting transport message", e);
		}

		return false;
	}

	@Override
	public String toString() {
		return String.format("Peer{%s, pubkey %s}", getAuthority(), connectionInfo.remoteStatic.toString().substring(0, 8));
	}

	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	record TransportWithSession(MessageTransport transport, EstablishedSession session) {
	}

	public record PeerConnectionInfo(NoisePublicKey remoteStatic, @Nullable NoisePresharedKey presharedKey,
									 @Nullable InetSocketAddress endpoint, @Nullable Duration keepaliveInterval) {
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
