package ax.xz.wireguard.noise.handshake;

import ax.xz.wireguard.noise.crypto.Poly1305;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305NonceSize;
import static java.lang.System.Logger.Level.INFO;

public final class SymmetricKeypair {
	private static final System.Logger log = System.getLogger(SymmetricKeypair.class.getName());

	private final byte[] sendKey;
	private final byte[] receiveKey;

	private final AtomicLong sendCounter = new AtomicLong(0);

	SymmetricKeypair(byte[] sendKey, byte[] receiveKey) {
		this.sendKey = sendKey;
		this.receiveKey = receiveKey;
	}

	public long cipher(ByteBuffer scratchBuffer, ByteBuffer src, ByteBuffer dst) {
		var nonce = sendCounter.getAndIncrement();
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(nonce);

		int srcLength = src.remaining();
		Poly1305.poly1305AeadEncrypt(scratchBuffer, new byte[0], sendKey, nonceBytes, src, dst.slice(dst.position(), srcLength), dst.slice(dst.position() + srcLength, 16));
		dst.position(dst.position() + srcLength + 16);

		return nonce;
	}

	public void decipher(ByteBuffer scratchBuffer, long counter, ByteBuffer src, ByteBuffer dst) throws BadPaddingException {
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(counter);
		Poly1305.poly1305AeadDecrypt(scratchBuffer, new byte[0], receiveKey, nonceBytes, src.slice(src.position(), src.limit() - src.position() - 16), dst, src.slice(src.limit() - 16, 16));
		src.position(src.limit());
		dst.position(dst.limit());
	}

	public int scratchBufferSize(ByteBuffer src, ByteBuffer dst) {
		return Poly1305.poly1305AeadBufferSize(src.remaining(), dst.remaining());
	}
}
