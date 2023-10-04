package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.TunPacketRouter;
import ax.xz.wireguard.device.message.PacketElement;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.UnencryptedOutgoingTransport;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.spi.PeerChannel;
import ax.xz.wireguard.util.IPFilter;
import ax.xz.wireguard.util.OrderedParallelProcessor;
import ax.xz.wireguard.util.PersistentTaskExecutor;
import ax.xz.wireguard.util.ThreadLocalPool;

import javax.annotation.WillClose;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.function.Function;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.WARNING;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * This class manages the encryption and decryption of inbound and outbound messages.
 *
 * <p>
 * Inbound transport packets from peers arrive at this class through the {@link #handleIncomingTransport(UndecryptedIncomingTransport)}
 * method, which sends them to an executor to be decrypted.  Once decrypted, they're sent up the network stack
 * through the {@link #interfaceBoundQueue} passed to the constructor.
 * </p>
 *
 * <p>
 * Outbound transport packets (which are captured when they're routed to a tun device) are sent to this class
 * through the {@link #sendOutgoingTransport(MemorySegment)} method, which sends them to an executor to be encrypted.
 * Once encrypted, they're sent over the network through the {@link EstablishedSession#sendOutgoingTransport(EncryptedOutgoingTransport)}
 * method if the passed {@link SessionManager} has a currently established session;  otherwise, they're dropped.
 * </p>
 */
class PeerTransportManager implements Runnable {
	private static final System.Logger logger = System.getLogger(PeerTransportManager.class.getName());

	private final OrderedParallelProcessor encryptionProcessor = new OrderedParallelProcessor();
	private final OrderedParallelProcessor decryptionProcessor = new OrderedParallelProcessor();

	private final SessionManager sessionManager;

	private final IPFilter packetFilter;
	private final NoisePrivateKey localIdentity;

	private final PeerChannel transportChannel;
	private final TunPacketRouter.TunPacketChannel tunChannel;

	PeerTransportManager(SessionManager sessionManager, NoisePrivateKey localIdentity, IPFilter packetFilter, PeerChannel transportChannel, TunPacketRouter.TunPacketChannel tunChannel) {
		this.transportChannel = transportChannel;
		this.tunChannel = tunChannel;

		this.sessionManager = sessionManager;
		this.packetFilter = packetFilter;
		this.localIdentity = localIdentity;
	}

	public void run() {
		try (var executor = new PersistentTaskExecutor<>(Function.identity(), logger, Thread.ofPlatform().factory())) {
			executor.submit("Transport manager:  incoming transport receiver", () -> {
				try (var pool = ThreadLocalPool.of(10)) {
					while (!Thread.interrupted()) {
						var transport = tunChannel.take();
						try (transport) {
							sendOutgoingTransport(pool, transport.get().packet());
						}
					}
				}
			});

			executor.submit("Transport manager:  incoming transport receiver", () -> {
				try (var pool = ThreadLocalPool.of(10)) {
					while (!Thread.interrupted()) {
						var buffer = new PacketElement.UnparsedIncomingPeerPacket(pool.acquire());

						try {
							var transport = buffer.initialise(transportChannel::receive, localIdentity);
							handleIncomingTransport((UndecryptedIncomingTransport) transport);
						} catch (BadPaddingException e) {
							buffer.close();
							logger.log(WARNING, "Failed to decrypt transport packet", e);
						} catch (Throwable e) {
							buffer.close();
							throw e;
						}
					}
				}
			});
		}
	}

	/**
	 * Sends the given transport data to the peer immediately.
	 *
	 * @param plaintext data to send
	 */
	public void sendOutgoingTransport(ThreadLocalPool pool, MemorySegment plaintext) throws InterruptedException {
		// get the session as close to the send as possible
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return;

		var packet = new UnencryptedOutgoingTransport(pool.acquire(), plaintext.byteSize() + 16, session.getRemoteIndex());

		try (var guard = encryptionProcessor.register()) {
			var outgoing = packet.fillCiphertext(ciphertext -> session.cipher(plaintext, ciphertext));
			encryptionProcessor.markCompleteAndRunOrdered(guard, () -> processEncryptedTransport(outgoing));
		}
	}

	/**
	 * Enqueues an inbound transport message to be processed and sent up the network stack.
	 * Releases the transport buffer when done with it
	 *
	 * @param ciphertextMessage the message to decrypt and send up the network stack
	 */
	public void handleIncomingTransport(@WillClose UndecryptedIncomingTransport ciphertextMessage) {
		// no use waiting for a session, since if the session is not established, we will not be able to decrypt the message
		// because any sessions created in the future will have a different keypair
		try {
			var currentSession = sessionManager.tryGetSessionNow();
			if (currentSession == null) {
				ciphertextMessage.close();
				return;
			}

			try (ciphertextMessage; var guard = decryptionProcessor.register()) {
				var result = ciphertextMessage.decrypt(currentSession::decryptTransportPacket);
				decryptionProcessor.markCompleteAndRunOrdered(guard, () -> processDecryptedTransport(result));
			}
		} catch (BadPaddingException e) {
			logger.log(WARNING, "Failed to decrypt transport packet", e);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	private void processEncryptedTransport(EncryptedOutgoingTransport transport) {
		var session = sessionManager.tryGetSessionNow();
		if (session == null) {
			logger.log(DEBUG, "Dropped packet because no session is established");
			transport.close();
			return;
		}

		try (transport) {
			transportChannel.send(transport.transmissiblePacket().asByteBuffer()); // TODO:  we should use the same session that was used to encrypt it
		} catch (IOException e) {
			logger.log(WARNING, "Failed to write packet to peer", e);
		}
	}

	/**
	 * Processes an inbound plaintext message
	 */
	private void processDecryptedTransport(DecryptedIncomingTransport transport) {
		var plaintext = transport.plaintextBuffer();

		try (transport) {
			if (plaintext.byteSize() == 0) {
				logger.log(DEBUG, "Received keepalive");
			} else if (!packetFilter.search(destinationIPOf(plaintext))) {
				logger.log(DEBUG, "Dropped packet with destination outside of allowed range");
			} else {
				try {
					tunChannel.send(transport);
				} catch (IOException e) {
					logger.log(WARNING, "Failed to write packet to tun device", e);
				}
			}
		}
	}

	/**
	 * Returns the destination IP address of the given packet.
	 */
	private static MemorySegment destinationIPOf(MemorySegment packet) {
		return switch (packet.get(JAVA_BYTE, 0) >> 4) {
			case 4 -> packet.asSlice(16, 4);
			case 6 -> packet.asSlice(24, 16);
			default -> throw new IllegalArgumentException("Unknown IP version");
		};
	}
}
