package ax.xz.wireguard.crypto;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static javax.crypto.Cipher.DECRYPT_MODE;

public class ChaCha20 {
	private static final ThreadLocal<Cipher> CIPHER_INSTANCE = ThreadLocal.withInitial(() -> {
		try {
			return Cipher.getInstance("ChaCha20");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new ExceptionInInitializerError(e);
		}
	});

	// Method to initialize the state matrix
	static void initializeState(byte[] key, byte[] nonce, int[] state, int counter) {
		if (state.length != 16) {
			throw new IllegalArgumentException("State size must be 16 words");
		}

		// Constants
		state[0] = 0x61707865;
		state[1] = 0x3320646e;
		state[2] = 0x79622d32;
		state[3] = 0x6b206574;

		// Key
		for (int i = 0; i < 8; i++) {
			state[4 + i] = byteArrayToIntLittleEndian(key, i * 4);
		}

		// Block counter
		state[12] = counter;

		// Nonce
		state[13] = byteArrayToIntLittleEndian(nonce, 0);
		state[14] = byteArrayToIntLittleEndian(nonce, 4);
		state[15] = byteArrayToIntLittleEndian(nonce, 8);
	}

	static int byteArrayToIntLittleEndian(byte[] b, int offset) {
		return (b[offset] & 0xFF) |
			   ((b[offset + 1] & 0xFF) << 8) |
			   ((b[offset + 2] & 0xFF) << 16) |
			   ((b[offset + 3] & 0xFF) << 24);
	}

	// Method to perform the quarter round operation
	static void quarterRound(int[] state, int a, int b, int c, int d) {
		state[a] += state[b]; state[d] ^= state[a]; state[d] = Integer.rotateLeft(state[d], 16);
		state[c] += state[d]; state[b] ^= state[c]; state[b] = Integer.rotateLeft(state[b], 12);
		state[a] += state[b]; state[d] ^= state[a]; state[d] = Integer.rotateLeft(state[d], 8);
		state[c] += state[d]; state[b] ^= state[c]; state[b] = Integer.rotateLeft(state[b], 7);
	}

	// Method to perform the ChaCha20 block function
	 static void chacha20Block(int[] state, byte[] output) {
		int[] workingState = state.clone();
		for (int i = 0; i < 10; i++) {
			doubleRound(workingState);
		}

		// Adding the original input words to the output words
		for (int i = 0; i < state.length; i++) {
			state[i] += workingState[i];
			output[i * 4] = (byte) state[i];
			output[i * 4 + 1] = (byte) (state[i] >> 8);
			output[i * 4 + 2] = (byte) (state[i] >> 16);
			output[i * 4 + 3] = (byte) (state[i] >> 24);
		}
	}

	static void doubleRound(int[] state) {
		quarterRound(state, 0, 4, 8, 12);
		quarterRound(state, 1, 5, 9, 13);
		quarterRound(state, 2, 6, 10, 14);
		quarterRound(state, 3, 7, 11, 15);

		quarterRound(state, 0, 5, 10, 15);
		quarterRound(state, 1, 6, 11, 12);
		quarterRound(state, 2, 7, 8, 13);
		quarterRound(state, 3, 4, 9, 14);
	}

	// Method to encrypt or decrypt data
	 static void chacha20(byte[] key, byte[] nonce, ByteBuffer src, ByteBuffer dst, int counter, boolean decrypting) {
		var cipher = CIPHER_INSTANCE.get();
		var sk = new SecretKeySpec(key, "ChaCha20-Poly1305");

		 try {
			 cipher.init(decrypting ? DECRYPT_MODE : Cipher.ENCRYPT_MODE, sk, new ChaCha20ParameterSpec(nonce, counter));
			 cipher.doFinal(src, dst);
		 } catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException |
				  IllegalBlockSizeException | BadPaddingException e) {
			 throw new RuntimeException(e);
		 }
	 }
}
