package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.noise.handshake.SymmetricKeypair;

import java.lang.foreign.MemorySegment;
import java.time.Duration;
import java.time.Instant;

final class EstablishedSession {
	private final SymmetricKeypair keypair;
	private final int remoteIndex;

	private final Duration keepaliveInterval;

	// TODO: make this configurable
	private final Instant expiration = Instant.now().plusSeconds(120);

	public EstablishedSession(SymmetricKeypair keypair, int remoteIndex, Duration keepaliveInterval) {
		this.keypair = keypair;

		this.remoteIndex = remoteIndex;
		this.keepaliveInterval = keepaliveInterval;
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

	@Override
	public String toString() {
		return "EstablishedSession[" +
			   "keypair=" + keypair + ", " + ']';
	}

	public boolean isExpired() {
		return Instant.now().isAfter(expiration);
	}

	public Duration getKeepaliveInterval() {
		return keepaliveInterval;
	}

	public int getRemoteIndex() {
		return remoteIndex;
	}
}
