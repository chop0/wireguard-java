package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.noise.handshake.SymmetricKeypair;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;

final class EstablishedSession implements AutoCloseable {
	private final SymmetricKeypair keypair;
	private final InetSocketAddress outboundPacketAddress;
	private final int remoteIndex;

	private final Duration keepaliveInterval;

	// TODO: make this configurable
	private final Instant expiration = Instant.now().plusSeconds(120);

	public EstablishedSession(SymmetricKeypair keypair, InetSocketAddress outboundPacketAddress, int remoteIndex, Duration keepaliveInterval) {
		this.keypair = keypair;
		this.outboundPacketAddress = outboundPacketAddress;

		this.remoteIndex = remoteIndex;
		this.keepaliveInterval = keepaliveInterval;
	}

	@Override
	public void close() throws InterruptedException {
		keypair.clean();
	}

	public void decryptTransportPacket(long counter, MemorySegment ciphertext, MemorySegment plaintext) {
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
