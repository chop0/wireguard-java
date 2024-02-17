package ax.xz.wireguard.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static java.lang.foreign.MemoryLayout.sequenceLayout;
import static java.lang.foreign.ValueLayout.*;
import static java.nio.ByteOrder.LITTLE_ENDIAN;

public class Poly1305 {
	private static final ThreadLocal<Cipher> CHACHA20_POLY1305 = ThreadLocal.withInitial(() -> {
		try {
			return Cipher.getInstance("ChaCha20-Poly1305");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new ExceptionInInitializerError(e);
		}
	});

	public static void poly1305AeadEncrypt(byte[] aad, byte[] key, byte[] nonce, ByteBuffer plaintext, ByteBuffer ciphertext) {
		var cipher = CHACHA20_POLY1305.get();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));

			cipher.updateAAD(aad);
			cipher.doFinal(plaintext, ciphertext);
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
				 IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

	public static void poly1305AeadDecrypt(byte[] aad, byte[] key, byte[] nonce, ByteBuffer ciphertext, ByteBuffer plaintext) throws AEADBadTagException {
		var cipher = CHACHA20_POLY1305.get();
		try {
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20-Poly1305"), new IvParameterSpec(nonce));

			cipher.updateAAD(aad);
			cipher.doFinal(ciphertext, plaintext);
		} catch (AEADBadTagException e) {
			throw e;
		} catch (BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
				 IllegalBlockSizeException e) {
			throw new RuntimeException(e);
		}
	}
}
