package ax.xz.wireguard.noise.handshake;

import ax.xz.wireguard.noise.crypto.chacha20poly1305;

import javax.crypto.BadPaddingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import static ax.xz.wireguard.noise.crypto.chacha20poly1305.NonceSize;

public final class SymmetricKeypair {
	private final byte[] sendKey;
	private final byte[] receiveKey;

	private final AtomicLong sendCounter = new AtomicLong(0);

	SymmetricKeypair(byte[] sendKey, byte[] receiveKey) {
		this.sendKey = sendKey;
		this.receiveKey = receiveKey;
	}

	public long cipher(ByteBuffer src, ByteBuffer dst) {
		var nonce = sendCounter.getAndIncrement();
		var nonceBytes = new byte[NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(nonce);

		chacha20poly1305.cipher(sendKey, src, dst, nonceBytes, new byte[0]);

		return nonce;
	}

	public void decipher(long counter, ByteBuffer src, ByteBuffer dst) throws BadPaddingException {
		var nonceBytes = new byte[NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(counter);

		chacha20poly1305.decipher(receiveKey, src, dst, nonceBytes, new byte[0]);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) return true;
		if (obj == null || obj.getClass() != this.getClass()) return false;
		var that = (SymmetricKeypair) obj;
		return Arrays.equals(this.sendKey, that.sendKey) &&
				Arrays.equals(this.receiveKey, that.receiveKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(Arrays.hashCode(sendKey), Arrays.hashCode(receiveKey));
	}

	@Override
	public String toString() {
		return "SymmetricKeypair[" +
			   "send=" + Arrays.toString(sendKey) + ", " +
			   "receive=" + Arrays.toString(receiveKey) + ']';
	}
}