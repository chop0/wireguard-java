package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;
import ax.xz.wireguard.noise.handshake.SymmetricKeypair;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static java.lang.System.Logger.Level.ERROR;

final class EstablishedSession implements AutoCloseable {
	private static final System.Logger log = System.getLogger(EstablishedSession.class.getName());

	private final SymmetricKeypair keypair;
	private final InetSocketAddress outboundPacketAddress;
	private final int remoteIndex;

	private final Duration keepaliveInterval;

	// TODO: make this configurable
	private final Instant expiration = Instant.now().plusSeconds(120);

	private final BufferedPacketStream buffer;

	public EstablishedSession(SymmetricKeypair keypair, InetSocketAddress outboundPacketAddress, int remoteIndex, Duration keepaliveInterval) throws IOException {
		this.keypair = keypair;
		this.outboundPacketAddress = outboundPacketAddress;

		this.remoteIndex = remoteIndex;
		this.keepaliveInterval = keepaliveInterval;

		buffer = new BufferedPacketStream(Duration.ofNanos(100_000));
	}

	@Override
	public void close() throws InterruptedException {
		buffer.close();
		keypair.clean();
	}

	/**
	 * Enqueues an encrypted transport packet to be sent to the connected peer over a UDP socket.
	 * @param packet the packet to be sent
	 * @return true if the packet was successfully enqueued
	 */
	public void sendOutgoingTransport(EncryptedOutgoingTransport packet) {
		buffer.transmit(packet, outboundPacketAddress);
	}

	public void decryptTransportPacket(long counter, MemorySegment ciphertext, MemorySegment plaintext) throws BadPaddingException {
		keypair.decipher(counter, ciphertext, plaintext);
	}

	/**
	 * @return the counter value used as a nonce for the packet
	 */
	public long cipher(MemorySegment plaintext, MemorySegment ciphertext) {
		return keypair.cipher(plaintext, ciphertext);
	}

	public InetSocketAddress getOutboundPacketAddress() {
		return outboundPacketAddress;
	}

	@Override
	public String toString() {
		return "EstablishedSession[" +
			   "keypair=" + keypair + ", " +
			   "remoteIndex=" + remoteIndex + ']';
	}

	public boolean isExpired() {
		return Instant.now().isAfter(expiration);
	}

	public int getRemoteIndex() {
		return remoteIndex;
	}

	public Duration getKeepaliveInterval() {
		return keepaliveInterval;
	}
}
