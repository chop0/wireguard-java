package ax.xz.wireguard.handshake;

import ax.xz.wireguard.crypto.Poly1305;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.AtomicLong;

import static ax.xz.wireguard.crypto.Crypto.ChaChaPoly1305NonceSize;

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
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(nonce);

		int srcLength = src.remaining();
		Poly1305.poly1305AeadEncrypt(new byte[0], sendKey, nonceBytes, src, dst.slice(dst.position(), srcLength + 16));
		dst.position(dst.position() + srcLength + 16);

		return nonce;
	}

	public void decipher(long counter, ByteBuffer src, ByteBuffer dst) throws AEADBadTagException {
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(counter);
		Poly1305.poly1305AeadDecrypt(new byte[0], receiveKey, nonceBytes, src, dst);
		src.position(src.limit());
		dst.position(dst.limit());
	}
}
