package ax.xz.wireguard.noise.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class Poly1305Test {
	private static final MethodHandle POLY1305_CONSTRUCTOR, POLY1305_ENGINE_INIT, POLY1305_ENGINE_UPDATE, POLY1305_ENGINE_DO_FINAL;

	static {
		try {
			var poly1305Class = Class.forName("com.sun.crypto.provider.Poly1305");
			POLY1305_CONSTRUCTOR = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findConstructor(poly1305Class, MethodType.methodType(void.class));
			POLY1305_ENGINE_INIT = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findVirtual(poly1305Class, "engineInit", MethodType.methodType(void.class, Key.class, AlgorithmParameterSpec.class));
			POLY1305_ENGINE_UPDATE = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findVirtual(poly1305Class, "engineUpdate", MethodType.methodType(void.class, byte[].class, int.class, int.class));
			POLY1305_ENGINE_DO_FINAL = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findVirtual(poly1305Class, "engineDoFinal", MethodType.methodType(byte[].class));
		} catch (NoSuchMethodException | IllegalAccessException | ClassNotFoundException e) {
			throw new RuntimeException(e);
		}
	}

	private static final byte[] TEST_KEY = {
		(byte) 0x85, (byte) 0xd6, (byte) 0xbe, (byte) 0x78, (byte) 0x57, (byte) 0x55, (byte) 0x6d, (byte) 0x33,
		(byte) 0x7f, (byte) 0x44, (byte) 0x52, (byte) 0xfe, (byte) 0x42, (byte) 0xd5, (byte) 0x06, (byte) 0xa8,
		(byte) 0x01, (byte) 0x03, (byte) 0x80, (byte) 0x8a, (byte) 0xfb, (byte) 0x0d, (byte) 0xb2, (byte) 0xfd,
		(byte) 0x4a, (byte) 0xbf, (byte) 0xf6, (byte) 0xaf, (byte) 0x41, (byte) 0x49, (byte) 0xf5, (byte) 0x1b
	};

	@Test
	void testPoly1305() {
		var text = "Cryptographic Forum Research Group";
		byte[] expectedTag = {(byte) 0xa8, (byte) 0x06, (byte) 0x1d, (byte) 0xc1, (byte) 0x30, (byte) 0x51, (byte) 0x36, (byte) 0xc6, (byte) 0xc2, (byte) 0x2b, (byte) 0x8b, (byte) 0xaf, (byte) 0x0c, (byte) 0x01, (byte) 0x27, (byte) 0xa9};

		var poly1305 = new NativePoly1305();

		poly1305.init(MemorySegment.ofArray(TEST_KEY));
		poly1305.update(MemorySegment.ofArray(text.getBytes()));

		var tag = poly1305.finish();
		assertArrayEquals(expectedTag, tag);
	}

	@Test
	void benchmarkPoly1305() throws Throwable {
		var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		var plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

		var key = new byte[32];
		ThreadLocalRandom.current().nextBytes(key);

		var keybb = ByteBuffer.allocateDirect(32);
		keybb.put(key);
		keybb.flip();

		var plaintextbb = ByteBuffer.allocateDirect(plaintextBytes.length);
		plaintextbb.put(plaintextBytes);
		plaintextbb.flip();

		var outbb = ByteBuffer.allocateDirect( 16);

		try (var arena = Arena.ofConfined()) {
			var context = arena.allocate(NativePoly1305.POLY1305_CONTEXT);
			var start = Instant.now();
			for (int i = 0; i < 1_000_000; i++) {
				plaintextbb.position(0);
				keybb.position(0);
				var poly1305 = new NativePoly1305(context);
				poly1305.init(MemorySegment.ofBuffer(keybb));
				poly1305.update(MemorySegment.ofBuffer(plaintextbb));
				poly1305.finish(MemorySegment.ofBuffer(outbb));
			}
			var end = Instant.now();

			System.out.println("Time taken with Poly1305(): " + Duration.between(start, end).toMillis());
		}

		{
			var start = Instant.now();
			byte[] serializedKey = new byte[1024];
			var state = Arena.ofAuto().allocate(16 * 4, 16);
			var nonce = Arena.ofAuto().allocate(12);
			for (int i = 0; i < 1_000_000; i++) {
				ChaCha20.initializeState(MemorySegment.ofBuffer(keybb), nonce, state, 0);
				ChaCha20.chacha20Block(state, MemorySegment.ofArray(serializedKey), 0);

				var poly1305 = POLY1305_CONSTRUCTOR.invoke();
				POLY1305_ENGINE_INIT.invoke(poly1305, (Key) new SecretKeySpec(serializedKey, 0, 32, "ChaCha20-Poly1305"), (AlgorithmParameterSpec) null);
				POLY1305_ENGINE_UPDATE.invoke(poly1305, plaintextBytes, 0, plaintextBytes.length);
				POLY1305_ENGINE_DO_FINAL.invoke(poly1305);
			}
			var end = Instant.now();

			System.out.println("Time taken with java poly1205(): " + Duration.between(start, end).toMillis());
		}
	}

	@Test
	void poly1305ChaChaKeyGen() {
		byte[] key = {
			(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83,
			(byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
			(byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b,
			(byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f,
			(byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93,
			(byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
			(byte) 0x98, (byte) 0x99, (byte) 0x9a, (byte) 0x9b,
			(byte) 0x9c, (byte) 0x9d, (byte) 0x9e, (byte) 0x9f
		};

		byte[] nonce = {
			(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
			(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
			(byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07
		};

		byte[] expectedOutput = {
			(byte) 0x8a, (byte) 0xd5, (byte) 0xa0, (byte) 0x8b,
			(byte) 0x90, (byte) 0x5f, (byte) 0x81, (byte) 0xcc,
			(byte) 0x81, (byte) 0x50, (byte) 0x40, (byte) 0x27,
			(byte) 0x4a, (byte) 0xb2, (byte) 0x94, (byte) 0x71,
			(byte) 0xa8, (byte) 0x33, (byte) 0xb6, (byte) 0x37,
			(byte) 0xe3, (byte) 0xfd, (byte) 0x0d, (byte) 0xa5,
			(byte) 0x08, (byte) 0xdb, (byte) 0xb8, (byte) 0xe2,
			(byte) 0xfd, (byte) 0xd1, (byte) 0xa6, (byte) 0x46
		};

		byte[] output = ChaCha20Poly1305.poly1305ChaChaKeyGen(key, nonce);
		assertArrayEquals(expectedOutput, output);
	}

	@Test
	void poly1305AeadEncrypt() {
		var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

		byte[] aad = {
			(byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53,
			(byte) 0xc0, (byte) 0xc1, (byte) 0xc2, (byte) 0xc3,
			(byte) 0xc4, (byte) 0xc5, (byte) 0xc6, (byte) 0xc7
		};

		byte[] key = {
			(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83,
			(byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
			(byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b,
			(byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f,
			(byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93,
			(byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
			(byte) 0x98, (byte) 0x99, (byte) 0x9a, (byte) 0x9b,
			(byte) 0x9c, (byte) 0x9d, (byte) 0x9e, (byte) 0x9f
		};

		byte[] nonce = {
			0x07, 0x00, 0x00, 0x00,
			0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47
		};

		byte[] expectedCiphertext = {
			(byte) 0xd3, (byte) 0x1a, (byte) 0x8d, (byte) 0x34, (byte) 0x64, (byte) 0x8e, (byte) 0x60, (byte) 0xdb, (byte) 0x7b, (byte) 0x86, (byte) 0xaf, (byte) 0xbc, (byte) 0x53, (byte) 0xef, (byte) 0x7e, (byte) 0xc2,
			(byte) 0xa4, (byte) 0xad, (byte) 0xed, (byte) 0x51, (byte) 0x29, (byte) 0x6e, (byte) 0x08, (byte) 0xfe, (byte) 0xa9, (byte) 0xe2, (byte) 0xb5, (byte) 0xa7, (byte) 0x36, (byte) 0xee, (byte) 0x62, (byte) 0xd6,
			(byte) 0x3d, (byte) 0xbe, (byte) 0xa4, (byte) 0x5e, (byte) 0x8c, (byte) 0xa9, (byte) 0x67, (byte) 0x12, (byte) 0x82, (byte) 0xfa, (byte) 0xfb, (byte) 0x69, (byte) 0xda, (byte) 0x92, (byte) 0x72, (byte) 0x8b,
			(byte) 0x1a, (byte) 0x71, (byte) 0xde, (byte) 0x0a, (byte) 0x9e, (byte) 0x06, (byte) 0x0b, (byte) 0x29, (byte) 0x05, (byte) 0xd6, (byte) 0xa5, (byte) 0xb6, (byte) 0x7e, (byte) 0xcd, (byte) 0x3b, (byte) 0x36,
			(byte) 0x92, (byte) 0xdd, (byte) 0xbd, (byte) 0x7f, (byte) 0x2d, (byte) 0x77, (byte) 0x8b, (byte) 0x8c, (byte) 0x98, (byte) 0x03, (byte) 0xae, (byte) 0xe3, (byte) 0x28, (byte) 0x09, (byte) 0x1b, (byte) 0x58,
			(byte) 0xfa, (byte) 0xb3, (byte) 0x24, (byte) 0xe4, (byte) 0xfa, (byte) 0xd6, (byte) 0x75, (byte) 0x94, (byte) 0x55, (byte) 0x85, (byte) 0x80, (byte) 0x8b, (byte) 0x48, (byte) 0x31, (byte) 0xd7, (byte) 0xbc,
			(byte) 0x3f, (byte) 0xf4, (byte) 0xde, (byte) 0xf0, (byte) 0x8e, (byte) 0x4b, (byte) 0x7a, (byte) 0x9d, (byte) 0xe5, (byte) 0x76, (byte) 0xd2, (byte) 0x65, (byte) 0x86, (byte) 0xce, (byte) 0xc6, (byte) 0x4b,
			(byte) 0x61, (byte) 0x16
		};

		byte[] expectedTag = {
			(byte) 0x1a, (byte) 0xe1, (byte) 0x0b, (byte) 0x59, (byte) 0x4f, (byte) 0x09, (byte) 0xe2, (byte) 0x6a, (byte) 0x7e, (byte) 0x90, (byte) 0x2e, (byte) 0xcb, (byte) 0xd0, (byte) 0x60, (byte) 0x06, (byte) 0x91
		};

		byte[] tag = new byte[16];
		byte[] ciphertext = new byte[plaintext.getBytes(StandardCharsets.UTF_8).length];
		ChaCha20Poly1305.poly1305AeadEncrypt(MemorySegment.ofArray(aad), MemorySegment.ofArray(key), MemorySegment.ofArray(nonce), MemorySegment.ofArray(plaintext.getBytes(StandardCharsets.UTF_8)), MemorySegment.ofArray(ciphertext), MemorySegment.ofArray(tag));

		assertArrayEquals(expectedCiphertext, ciphertext);
		assertArrayEquals(expectedTag, tag);
	}

	@Test
	void poly1305AeadDecrypt() throws AEADBadTagException {
		var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		var aad = "Cryptographic Forum Research Group";
		var key = new byte[32];
		ThreadLocalRandom.current().nextBytes(key);

		var nonce = new byte[12];
		ThreadLocalRandom.current().nextBytes(nonce);

		byte[] tag = new byte[16];
		byte[] ciphertext = new byte[plaintext.getBytes(StandardCharsets.UTF_8).length];
		ChaCha20Poly1305.poly1305AeadEncrypt(MemorySegment.ofArray(aad.getBytes(StandardCharsets.UTF_8)), MemorySegment.ofArray(key), MemorySegment.ofArray(nonce), MemorySegment.ofArray(plaintext.getBytes(StandardCharsets.UTF_8)), MemorySegment.ofArray(ciphertext), MemorySegment.ofArray(tag));

		byte[] result = new byte[plaintext.getBytes(StandardCharsets.UTF_8).length];
		ChaCha20Poly1305.poly1305AeadDecrypt(MemorySegment.ofArray(aad.getBytes(StandardCharsets.UTF_8)), MemorySegment.ofArray(key), MemorySegment.ofArray(nonce), MemorySegment.ofArray(ciphertext), MemorySegment.ofArray(result), MemorySegment.ofArray(tag));
		assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), result);

		tag[0] ^= 0x01;
		assertThrows(AEADBadTagException.class, () -> ChaCha20Poly1305.poly1305AeadDecrypt(MemorySegment.ofArray(aad.getBytes(StandardCharsets.UTF_8)), MemorySegment.ofArray(key), MemorySegment.ofArray(nonce), MemorySegment.ofArray(ciphertext), MemorySegment.ofArray(result), MemorySegment.ofArray(tag)));
	}
}
