package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.PeerPacketRouter;
import ax.xz.wireguard.device.TunPacketRouter;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.UnencryptedOutgoingTransport;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.util.Pool;
import ax.xz.wireguard.util.ReferenceCounted;

import javax.annotation.WillClose;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.ForkJoinPool;

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

	private final OrderedCryptographicExecutor<DecryptionTask, DecryptedIncomingTransport> decryptionProcessor = new OrderedCryptographicExecutor<>(ForkJoinPool.getCommonPoolParallelism(), DecryptionTask::decrypt, (error, task) -> {
		logger.log(WARNING, "Failed to decrypt transport message", error);
		task.transport().close();
	});
	private final Pool pool;
	private final PeerPacketRouter.PeerPacketChannel peerChannel;
	private final TunPacketRouter.TunPacketChannel tunChannel;
	private final PeerConnectionInfo connectionInfo;
	private final SessionManager sessionManager;
	private final OrderedCryptographicExecutor<ReferenceCounted<IncomingTunnelPacket>, EncryptedOutgoingTransport> encryptionProcessor = new OrderedCryptographicExecutor<>(ForkJoinPool.getCommonPoolParallelism(), this::encrypt, (error, transport) -> {
//		logger.log(WARNING, "Failed to encrypt transport message", error);
	});

	PeerTransportManager(Pool pool, PeerPacketRouter.PeerPacketChannel peerChannel, TunPacketRouter.TunPacketChannel tunChannel, PeerConnectionInfo connectionInfo, SessionManager sessionManager) {
		this.pool = pool;
		this.peerChannel = peerChannel;
		this.tunChannel = tunChannel;
		this.connectionInfo = connectionInfo;
		this.sessionManager = sessionManager;
	}

	public void run() {
		var incomingPacketReceiver = new Thread(() -> {
			try {
				while (!Thread.interrupted()) {
					var transport = tunChannel.take();
					sendOutgoingTransport(transport);
				}
			} catch (InterruptedException e) {
				logger.log(DEBUG, "Transport manager interrupted", e);
				Thread.currentThread().interrupt();
			} catch (Exception e) {
				logger.log(WARNING, "Transport manager failed", e);
			}
		}, "Transport manager:  incoming transport receiver");

		var incomingTransportReceiver = new Thread(() -> {
			try {
				while (!Thread.interrupted()) {
					var transport = peerChannel.takeTransport();
					handleIncomingTransport(transport);
				}
			} catch (InterruptedException e) {
				logger.log(DEBUG, "Transport manager interrupted", e);
				Thread.currentThread().interrupt();
			} catch (Exception e) {
				logger.log(WARNING, "Transport manager failed", e);
			}
		}, "Transport manager:  incoming transport receiver");

		var encryptedProcessor = new Thread(() -> {
			try {
				while (!Thread.interrupted()) {
					var task = encryptionProcessor.dequeue();
					processEncryptedTransport(task);
				}
			} catch (InterruptedException e) {
				logger.log(DEBUG, "Transport manager interrupted", e);
				Thread.currentThread().interrupt();
			} catch (Exception e) {
				logger.log(WARNING, "Transport manager failed", e);
			}
		}, "Transport manager:  encryption processor");

		var decryptedProcessor = new Thread(() -> {
			try {
				while (!Thread.interrupted()) {
					var task = decryptionProcessor.dequeue();
					processDecryptedTransport(task);
				}
			} catch (InterruptedException e) {
				logger.log(DEBUG, "Transport manager interrupted", e);
				Thread.currentThread().interrupt();
			} catch (Exception e) {
				logger.log(WARNING, "Transport manager failed", e);
			}
		}, "Transport manager:  decryption processor");

		incomingPacketReceiver.start();
		incomingTransportReceiver.start();
		encryptedProcessor.start();
		decryptedProcessor.start();

		try {
			incomingPacketReceiver.join();
			incomingTransportReceiver.join();
			encryptedProcessor.join();
			decryptedProcessor.join();
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Transport manager interrupted", e);
			Thread.currentThread().interrupt();
		}
	}

	/**
	 * Enqueues an inbound transport message to be processed and sent up the network stack.
	 * Releases the transport buffer when done with it
	 *
	 * @param ciphertextMessage the message to decrypt and send up the network stack
	 */
	void handleIncomingTransport(@WillClose UndecryptedIncomingTransport ciphertextMessage) {
		// no use waiting for a session, since if the session is not established, we will not be able to decrypt the message
		// because any sessions created in the future will have a different keypair
		var currentSession = sessionManager.tryGetSessionNow();
		if (currentSession == null) {
			ciphertextMessage.close();
			return;
		}

		if (!decryptionProcessor.enqueue(new DecryptionTask(currentSession, ciphertextMessage))) {
			logger.log(DEBUG, "Dropped packet because decryption processor is full");
			ciphertextMessage.close();
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
			peerChannel.send(transport); // TODO:  we should use the same session that was used to encrypt it
		} catch (IOException e) {
			logger.log(WARNING, "Failed to write packet to peer", e);
		}
	}

	/**
	 * Processes an inbound plaintext message
	 */
	private void processDecryptedTransport(DecryptedIncomingTransport transport) throws InterruptedException {
		var plaintext = transport.plaintextBuffer();

		try (transport) {
			if (plaintext.byteSize() == 0) {
				logger.log(DEBUG, "Received keepalive");
			} else if (false && !connectionInfo.filter().search(destinationIPOf(plaintext))) {
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

	/**
	 * Sends the given transport data to the peer immediately.
	 *
	 * @param plaintext data to send
	 */
	void sendOutgoingTransportNow(MemorySegment plaintext) {
		// get the session as close to the send as possible
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return;

		var packet = new UnencryptedOutgoingTransport(pool.acquire(), plaintext.byteSize() + 16, session.getRemoteIndex());

		var outgoing = packet.fillCiphertext(ciphertext -> session.cipher(plaintext, ciphertext));
		processEncryptedTransport(outgoing);
	}

	private EncryptedOutgoingTransport encrypt(ReferenceCounted<IncomingTunnelPacket> guard) {
		try (guard) {
			var session = sessionManager.tryGetSessionNow();
			if (session == null) {
				throw new IllegalStateException("No session is established");
			}

			var plaintext = guard.get().packet();

			var packet = new UnencryptedOutgoingTransport(pool.acquire(), plaintext.byteSize() + 16, session.getRemoteIndex());
			return packet.fillCiphertext(ciphertext -> session.cipher(plaintext, ciphertext));
		}
	}

	/**
	 * Enqueues an outbound transport message to be encrypted and sent to the peer.
	 */
	void sendOutgoingTransport(ReferenceCounted<IncomingTunnelPacket> guard) {
		if (!encryptionProcessor.enqueue(guard)) {
			logger.log(DEBUG, "Dropped packet because encryption processor is full");
			guard.close();
		}
	}


	record DecryptionTask(EstablishedSession session, UndecryptedIncomingTransport transport) {
		DecryptedIncomingTransport decrypt() throws BadPaddingException {
			return transport.decrypt(session::decryptTransportPacket);
		}
	}
}
