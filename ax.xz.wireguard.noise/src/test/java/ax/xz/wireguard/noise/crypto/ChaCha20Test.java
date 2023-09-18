package ax.xz.wireguard.noise.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class ChaCha20Test {

	@Test
	void quarterRound() {
		{
			int[] state = {
				0x11111111,
				0x01020304,
				0x9b8d6f43,
				0x01234567
			};
			int[] expectedOutput = {
				0xea2a92f4,
				0xcb1cf8ce,
				0x4581472e,
				0x5881c4bb
			};

			state[0] += state[1];
			state[3] ^= state[0];
			state[3] = Integer.rotateLeft(state[3], 16);
			state[2] += state[3];
			state[1] ^= state[2];
			state[1] = Integer.rotateLeft(state[1], 12);
			state[0] += state[1];
			state[3] ^= state[0];
			state[3] = Integer.rotateLeft(state[3], 8);
			state[2] += state[3];
			state[1] ^= state[2];
			state[1] = Integer.rotateLeft(state[1], 7);
			assertArrayEquals(expectedOutput, state);
		}

		{
			int[] state = {
				0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
				0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
				0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
				0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
			};
			int[] expectedOutput = {
				0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
				0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
				0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
				0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
			};

			state[2] += state[7];
			state[13] ^= state[2];
			state[13] = Integer.rotateLeft(state[13], 16);
			state[8] += state[13];
			state[7] ^= state[8];
			state[7] = Integer.rotateLeft(state[7], 12);
			state[2] += state[7];
			state[13] ^= state[2];
			state[13] = Integer.rotateLeft(state[13], 8);
			state[8] += state[13];
			state[7] ^= state[8];
			state[7] = Integer.rotateLeft(state[7], 7);
			assertArrayEquals(expectedOutput, state);
		}
	}

	private static final byte[] TEST_KEY = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f
	};
	private static final byte[] TEST_NONCE_0 = {
		0x00, 0x00, 0x00, 0x09,
		0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00
	};

	private static final byte[] TEST_NONCE_1 = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00
	};

	@Test
	void initializeState() {
		{
			int[] expectedOutput = {
				0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
				0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
				0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
				0x00000001, 0x09000000, 0x4a000000, 0x00000000
			};

			int[] state = new int[16];
			ChaCha20.initializeState(TEST_KEY, TEST_NONCE_0, state, 1);
			assertArrayEquals(expectedOutput, state);
		}
	}


	@Test
	void doubleRound() {
		int[] expectedInnerBlock = {
			0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f,
			0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7,
			0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd,
			0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2
		};

		int[] state = new int[16];
		ChaCha20.initializeState(TEST_KEY, TEST_NONCE_0, state, 1);

		var mem = Arena.ofAuto().allocate(64);
		mem.copyFrom(MemorySegment.ofArray(state));
		for (int i = 0; i < 10; i++) {
			ChaCha20.doubleRound(mem);
		}
		MemorySegment.ofArray(state).copyFrom(mem);
		assertArrayEquals(expectedInnerBlock, state);
	}

	@Test
	void chacha20Block() {
		byte[] expectedOutputByte = {
			(byte) 0x10, (byte) 0xf1, (byte) 0xe7, (byte) 0xe4, (byte) 0xd1, (byte) 0x3b, (byte) 0x59, (byte) 0x15, (byte) 0x50, (byte) 0x0f, (byte) 0xdd, (byte) 0x1f, (byte) 0xa3, (byte) 0x20, (byte) 0x71, (byte) 0xc4,
			(byte) 0xc7, (byte) 0xd1, (byte) 0xf4, (byte) 0xc7, (byte) 0x33, (byte) 0xc0, (byte) 0x68, (byte) 0x03, (byte) 0x04, (byte) 0x22, (byte) 0xaa, (byte) 0x9a, (byte) 0xc3, (byte) 0xd4, (byte) 0x6c, (byte) 0x4e,
			(byte) 0xd2, (byte) 0x82, (byte) 0x64, (byte) 0x46, (byte) 0x07, (byte) 0x9f, (byte) 0xaa, (byte) 0x09, (byte) 0x14, (byte) 0xc2, (byte) 0xd7, (byte) 0x05, (byte) 0xd9, (byte) 0x8b, (byte) 0x02, (byte) 0xa2,
			(byte) 0xb5, (byte) 0x12, (byte) 0x9c, (byte) 0xd1, (byte) 0xde, (byte) 0x16, (byte) 0x4e, (byte) 0xb9, (byte) 0xcb, (byte) 0xd0, (byte) 0x83, (byte) 0xe8, (byte) 0xa2, (byte) 0x50, (byte) 0x3c, (byte) 0x4e
		};
		int[] expectedOutput = new int[16];
		MemorySegment.ofArray(expectedOutput).copyFrom(MemorySegment.ofArray(expectedOutputByte));

		int[] state = new int[16];
		ChaCha20.initializeState(TEST_KEY, TEST_NONCE_0, state, 1);

		var output = Arena.global().allocate(64, 4);
		ChaCha20.chacha20Block(state, output, 1);

		assertArrayEquals(expectedOutput, output.toArray(ValueLayout.JAVA_INT));
	}

	private static void hexPrint(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			System.out.printf("0x%02x, ", bytes[i]);
			if (i % 16 == 15) {
				System.out.println();
			}
		}
		System.out.println();
	}

	@Test
	void chacha20() {
		var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		//   Ciphertext Sunscreen:
		byte[] expectedCiphertext = {
			(byte) 0x6e, (byte) 0x2e, (byte) 0x35, (byte) 0x9a, (byte) 0x25, (byte) 0x68, (byte) 0xf9, (byte) 0x80, (byte) 0x41, (byte) 0xba, (byte) 0x07, (byte) 0x28, (byte) 0xdd, (byte) 0x0d, (byte) 0x69, (byte) 0x81,
			(byte) 0xe9, (byte) 0x7e, (byte) 0x7a, (byte) 0xec, (byte) 0x1d, (byte) 0x43, (byte) 0x60, (byte) 0xc2, (byte) 0x0a, (byte) 0x27, (byte) 0xaf, (byte) 0xcc, (byte) 0xfd, (byte) 0x9f, (byte) 0xae, (byte) 0x0b,
			(byte) 0xf9, (byte) 0x1b, (byte) 0x65, (byte) 0xc5, (byte) 0x52, (byte) 0x47, (byte) 0x33, (byte) 0xab, (byte) 0x8f, (byte) 0x59, (byte) 0x3d, (byte) 0xab, (byte) 0xcd, (byte) 0x62, (byte) 0xb3, (byte) 0x57,
			(byte) 0x16, (byte) 0x39, (byte) 0xd6, (byte) 0x24, (byte) 0xe6, (byte) 0x51, (byte) 0x52, (byte) 0xab, (byte) 0x8f, (byte) 0x53, (byte) 0x0c, (byte) 0x35, (byte) 0x9f, (byte) 0x08, (byte) 0x61, (byte) 0xd8,
			(byte) 0x07, (byte) 0xca, (byte) 0x0d, (byte) 0xbf, (byte) 0x50, (byte) 0x0d, (byte) 0x6a, (byte) 0x61, (byte) 0x56, (byte) 0xa3, (byte) 0x8e, (byte) 0x08, (byte) 0x8a, (byte) 0x22, (byte) 0xb6, (byte) 0x5e,
			(byte) 0x52, (byte) 0xbc, (byte) 0x51, (byte) 0x4d, (byte) 0x16, (byte) 0xcc, (byte) 0xf8, (byte) 0x06, (byte) 0x81, (byte) 0x8c, (byte) 0xe9, (byte) 0x1a, (byte) 0xb7, (byte) 0x79, (byte) 0x37, (byte) 0x36,
			(byte) 0x5a, (byte) 0xf9, (byte) 0x0b, (byte) 0xbf, (byte) 0x74, (byte) 0xa3, (byte) 0x5b, (byte) 0xe6, (byte) 0xb4, (byte) 0x0b, (byte) 0x8e, (byte) 0xed, (byte) 0xf2, (byte) 0x78, (byte) 0x5e, (byte) 0x42,
			(byte) 0x87, (byte) 0x4d
		};

		byte[] result = new byte[plaintext.length()];
		ChaCha20.chacha20(TEST_KEY, TEST_NONCE_1, MemorySegment.ofArray(plaintext.getBytes(StandardCharsets.UTF_8)), MemorySegment.ofArray(result), 1);
		assertArrayEquals(expectedCiphertext, result);
	}

	@Test
	void benchmarkCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		try (var arena = Arena.ofConfined()) {

			var key = new byte[32];
			ThreadLocalRandom.current().nextBytes(key);

			var nonce = new byte[12];
			var plaintextBytes = new byte[1024];
			ThreadLocalRandom.current().nextBytes(plaintextBytes);

			var plaintextMem = arena.allocate(plaintextBytes.length);
			plaintextMem.copyFrom(MemorySegment.ofArray(plaintextBytes));

			byte[] ciphertext = new byte[plaintextBytes.length];
			var ciphertextMem = arena.allocate(ciphertext.length, 16);

			{
				// warm up
				for (int i = 0; i < 100_000; i++) {
					ChaCha20.chacha20(key, nonce, plaintextMem, ciphertextMem, 0);
				}

				int hashcode = 0;
				var start = Instant.now();
				for (int i = 0; i < 100_000; i++) {
					ChaCha20.chacha20(key, nonce, plaintextMem, ciphertextMem, 0);
					hashcode ^= Arrays.hashCode(ciphertextMem.toArray(ValueLayout.JAVA_INT));
				}
				var end = Instant.now();

				System.out.println(hashcode); // stop jit from optimizing away the loop

				double nanosPerByte = Duration.between(start, end).toNanos() / (plaintextBytes.length * 100_000D);
				System.out.println(STR."Time taken with homemade chacha20: \{Duration.between(start, end).toMillis()} ms total, \{nanosPerByte} ns/byte");
			}

			{
				var sk = new SecretKeySpec(key, "ChaCha20-Poly1305");

				// warm up
				for (int i = 0; i < 100_000; i++) {
					var cipher = Cipher.getInstance("ChaCha20");
					cipher.init(Cipher.ENCRYPT_MODE, sk, new ChaCha20ParameterSpec(nonce, 0));
					cipher.doFinal(plaintextBytes);
				}

				int hashcode = 0;
				var start = Instant.now();
				for (int i = 0; i < 100_000; i++) {
					var cipher = Cipher.getInstance("ChaCha20");
					cipher.init(Cipher.ENCRYPT_MODE, sk, new ChaCha20ParameterSpec(nonce, 0));
					cipher.doFinal(plaintextBytes);
					hashcode ^= Arrays.hashCode(ciphertextMem.toArray(ValueLayout.JAVA_INT));
				}
				var end = Instant.now();

				System.out.println(hashcode); // stop jit from optimizing away the loop

				double nanosPerByte = Duration.between(start, end).toNanos() / (plaintextBytes.length * 100_000D);
				System.out.println(STR."Time taken with java jce cipher: \{Duration.between(start, end).toMillis()} ms total, \{nanosPerByte} ns/byte");
			}
		}
	}

	@Test
	void testMatchesCipher() throws ShortBufferException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

		var nonce = new byte[12];
		var key = new byte[32];
		ThreadLocalRandom.current().nextBytes(key);

		var ciphertextAndTagCipher = ByteBuffer.allocate(plaintext.length());

		{
			var src = ByteBuffer.wrap(plaintext.getBytes(StandardCharsets.UTF_8));
			var sk = new SecretKeySpec(key, "ChaCha20");

			var cipher = Cipher.getInstance("ChaCha20");
			cipher.init(Cipher.ENCRYPT_MODE, sk, new ChaCha20ParameterSpec(nonce, 0));
			cipher.doFinal(src, ciphertextAndTagCipher);
		}

		byte[] ciphertextAndTag = new byte[plaintext.length()];
		ChaCha20.chacha20(key, nonce, MemorySegment.ofArray(plaintext.getBytes(StandardCharsets.UTF_8)), MemorySegment.ofArray(ciphertextAndTag), 0);

		assertArrayEquals(ciphertextAndTag, ciphertextAndTagCipher.array());
	}
}