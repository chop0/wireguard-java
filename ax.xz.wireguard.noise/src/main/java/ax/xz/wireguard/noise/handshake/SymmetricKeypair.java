package ax.xz.wireguard.noise.handshake;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicLong;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305NonceSize;

public final class SymmetricKeypair {
	private final SecretKey sendKey;
	private final SecretKey receiveKey;

	private static final ThreadLocal<Cipher> cipher = ThreadLocal.withInitial(() -> {
		try {
			return Cipher.getInstance("ChaCha20-Poly1305");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	});

	private final AtomicLong sendCounter = new AtomicLong(0);

	SymmetricKeypair(SecretKey sendKey, SecretKey receiveKey) {
		this.sendKey = sendKey;
		this.receiveKey = receiveKey;
	}

	public long cipher(ByteBuffer src, ByteBuffer dst) throws ShortBufferException {
		var nonce = sendCounter.getAndIncrement();
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(nonce);

		var cipher = SymmetricKeypair.cipher.get();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, sendKey, new IvParameterSpec(nonceBytes));
			cipher.doFinal(src, dst);
		} catch (
			IllegalBlockSizeException |
			BadPaddingException |
			InvalidAlgorithmParameterException |
			InvalidKeyException e
		) {
			throw new RuntimeException(e);
		}

		return nonce;
	}

	public void decipher(long counter, ByteBuffer src, ByteBuffer dst) throws BadPaddingException {
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(counter);

		var cipher = SymmetricKeypair.cipher.get();
		try {
			cipher.init(Cipher.DECRYPT_MODE, receiveKey, new IvParameterSpec(nonceBytes));
			cipher.doFinal(src, dst);
		} catch (ShortBufferException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException(e);
		} catch (IllegalBlockSizeException e) {
			throw new Error("unexpected error (we're using a stream cipher)", e);
		} catch (AEADBadTagException e) {
			var a = 1;
		}
	}
}
