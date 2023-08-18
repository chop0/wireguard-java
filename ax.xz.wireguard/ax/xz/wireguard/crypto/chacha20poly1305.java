package ax.xz.wireguard.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;

public class chacha20poly1305 {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static final int KeySize = 32;
	public static final int NonceSize = 12;
	public static final int Overhead = 16;

	private chacha20poly1305() {}

	interface CipherHolder {
		ThreadLocal<Cipher> holder = ThreadLocal.withInitial(() -> {
			try {
				return Cipher.getInstance("ChaCha20-Poly1305", "BC");
			} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
				throw new RuntimeException(e);
			}
		});
	}

	private static Cipher getCipher() {
		return CipherHolder.holder.get();
	}

	public static void cipher(byte[] key, ByteBuffer plaintext, ByteBuffer dst, byte[] nonce, byte[] additionalData) {
		if (key.length != KeySize) {
			throw new IllegalArgumentException("chacha20poly1305: bad key length passed to cipher");
		}

		if (dst.remaining() < plaintext.remaining() + 16) {
			throw new IllegalArgumentException("chacha20poly1305: destination too short");
		}

		if (nonce.length != NonceSize) {
			throw new IllegalArgumentException("chacha20poly1305: bad nonce length passed to cipher");
		}

		var cipher = getCipher();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}

		try {
			cipher.updateAAD(additionalData);
			cipher.doFinal(plaintext, dst);
		} catch (ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public static void decipher(byte[] key, ByteBuffer ciphertext, ByteBuffer dst, byte[] nonce, byte[] additionalData) throws BadPaddingException {
		if (key.length != KeySize) {
			throw new IllegalArgumentException("chacha20poly1305: bad key length passed to decipher");
		}

		if (ciphertext.remaining() < 16) {
			throw new IllegalArgumentException("chacha20poly1305: ciphertext too short");
		}

		if (dst.remaining() < ciphertext.remaining() - 16) {
			throw new IllegalArgumentException("chacha20poly1305: destination too short");
		}

		if (nonce.length != NonceSize) {
			throw new IllegalArgumentException("chacha20poly1305: bad nonce length passed to decipher");
		}

		var cipher = getCipher();
		try {
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));

			cipher.updateAAD(additionalData);
			cipher.doFinal(ciphertext, dst);
		} catch (ShortBufferException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new Error("unexpected error (should have failed validation at beginning of method)", e);
		} catch (IllegalBlockSizeException e) {
			throw new Error("unexpected error (we're using a stream cipher)", e);
		}
	}
}
