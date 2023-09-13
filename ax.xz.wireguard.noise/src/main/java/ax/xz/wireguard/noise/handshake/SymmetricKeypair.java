package ax.xz.wireguard.noise.handshake;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305NonceSize;
import static java.lang.System.Logger.Level.INFO;

public final class SymmetricKeypair {
	private static final System.Logger log = System.getLogger(SymmetricKeypair.class.getName());

	private final SecretKey sendKey;
	private final SecretKey receiveKey;

	private final AtomicLong sendCounter = new AtomicLong(0);

	SymmetricKeypair(SecretKey sendKey, SecretKey receiveKey) {
		this.sendKey = sendKey;
		this.receiveKey = receiveKey;
	}

	private static final ConcurrentLinkedQueue<Cipher> cipherPool = new ConcurrentLinkedQueue<>();
	private Cipher getCipher() {
		var cipher = cipherPool.poll();
		if (cipher == null) {
			try {
				cipher = Cipher.getInstance("ChaCha20-Poly1305");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new RuntimeException(e);
			}
		}
		return cipher;
	}

	private void releaseCipher(Cipher cipher) {
		cipherPool.add(cipher);
	}


	public long cipher(ByteBuffer src, ByteBuffer dst) throws ShortBufferException {
		var nonce = sendCounter.getAndIncrement();
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(nonce);

		var cipher = getCipher();
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
		} finally {
			releaseCipher(cipher);
		}

		return nonce;
	}

	public void decipher(long counter, ByteBuffer src, ByteBuffer dst) throws BadPaddingException, ShortBufferException {
		var nonceBytes = new byte[ChaChaPoly1305NonceSize];
		ByteBuffer.wrap(nonceBytes).order(ByteOrder.LITTLE_ENDIAN).position(4).putLong(counter);

		var oldSrcLimit = src.remaining();
		var oldDstLimit = dst.remaining();

		var cipher = getCipher();
		try {
			cipher.init(Cipher.DECRYPT_MODE, receiveKey, new IvParameterSpec(nonceBytes));
			cipher.doFinal(src, dst);
		} catch (ShortBufferException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new IllegalArgumentException(e);
		} catch (IllegalBlockSizeException e) {
			throw new Error("unexpected error (we're using a stream cipher)", e);
		} catch (AEADBadTagException ex) {
			log.log(INFO, "counter is {0}, src.remaining() is {1}, dst.remaining() is {2}", counter, oldSrcLimit, oldDstLimit);
			throw new ShortBufferException();
		} finally {
			releaseCipher(cipher);
		}
	}
}
