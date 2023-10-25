package ax.xz.wireguard.device.peer;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.Pool;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.UnencryptedOutgoingTransport;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.util.IPFilter;
import ax.xz.wireguard.util.ReferenceCounted;

import javax.annotation.WillClose;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.*;

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
class TransportManager implements Runnable {
	private static final System.Logger logger = System.getLogger(TransportManager.class.getName());

	private final IPFilter destinationFilter;
	private final SessionManager sessionManager;
	private final Pool pool;

	/**
	 * A queue of packets to be sent up the network stack through a tun device.
	 */
	private final Tun tun;

	TransportManager(IPFilter destinationFilter, SessionManager sessionManager, Pool pool, Tun tun) {
		this.destinationFilter = destinationFilter;
		this.sessionManager = sessionManager;
		this.pool = pool;
		this.tun = tun;
	}

	public void run() {
		// we don't need to do anything here
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

		decryptAndEnqueue(ciphertextMessage, currentSession);
	}

	/**
	 * Enqueues an outbound transport message to be encrypted and sent to the peer.
	 */
	void sendOutgoingTransport(ReferenceCounted<IncomingTunnelPacket> guard) {
		try (guard) {
			sendOutgoingTransportNow(guard.get().packet());
		}
	}

	/**
	 * Decrypts a transport message and enqueues it to be sent up the network stack.
	 */
	private void decryptAndEnqueue(@WillClose UndecryptedIncomingTransport transport, EstablishedSession session) {
		try {
			var decryptedTransport = transport.decrypt(session::decryptTransportPacket);
			processDecryptedTransport(decryptedTransport);
		} catch (BadPaddingException e) {
			logger.log(WARNING, "Received transport message with invalid padding");
			transport.close();
		}
	}

	/**
	 * Processes an inbound plaintext message
	 */
	private void processDecryptedTransport(DecryptedIncomingTransport transport) {
		var plaintext = transport.plaintextBuffer();

		if (plaintext.byteSize() == 0) {
			logger.log(DEBUG, "Received keepalive");
		} else if (!destinationFilter.search(destinationIPOf(plaintext))) {
			logger.log(DEBUG, "Dropped packet with destination outside of allowed range");
		} else {
			try {
				tun.write(transport.plaintextBuffer().asByteBuffer());
			} catch (IOException e) {
				logger.log(WARNING, "Dropped decrypted packet on its way to the tun device", e);
			}
		}

		transport.close();
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
		if (session == null) {
			logger.log(WARNING, "Dropping packet because no session established");
			return;
		}

		var packet = new UnencryptedOutgoingTransport(pool.acquire(), plaintext.byteSize() + 16, session.getRemoteIndex());

		var outgoing = packet.fillCiphertext(ciphertext -> session.cipher(plaintext, ciphertext));
		session.sendOutgoingTransport(outgoing);
	}


}
