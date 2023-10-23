package ax.xz.wireguard.noise.crypto;

import javax.crypto.AEADBadTagException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.Arrays;

import static java.lang.foreign.ValueLayout.*;

public class ChaCha20Poly1305 {
	public static void poly1305ChaChaKeyGen(MemorySegment chacha20StateBuffer, MemorySegment key, MemorySegment nonce, MemorySegment output) {
		ChaCha20.initializeState(key, nonce, chacha20StateBuffer, 0);
		ChaCha20.chacha20Block(chacha20StateBuffer, output, 0);
	}

	public static byte[] poly1305ChaChaKeyGen(byte[] key, byte[] nonce) {
		try (var arena = Arena.ofConfined()) {
			var chacha20State = arena.allocateArray(JAVA_INT, 16);
			var output = arena.allocateArray(JAVA_BYTE, 64);
			var keySegment = arena.allocateArray(JAVA_BYTE, 32);
			var nonceSegment = arena.allocateArray(JAVA_BYTE, 12);

			keySegment.copyFrom(MemorySegment.ofArray(key));
			nonceSegment.copyFrom(MemorySegment.ofArray(nonce));

			poly1305ChaChaKeyGen(chacha20State, keySegment, nonceSegment, output);
			return output.asSlice(0, 32).toArray(JAVA_BYTE);
		}
	}

	public static void poly1305AeadEncrypt(MemorySegment key, MemorySegment nonce, MemorySegment plaintext, MemorySegment ciphertext, MemorySegment tag) {
		poly1305AeadEncrypt(null, key, nonce, plaintext, ciphertext, tag);
	}

	public static void poly1305AeadEncrypt(MemorySegment aad, MemorySegment key, MemorySegment nonce, MemorySegment plaintext, MemorySegment ciphertext, MemorySegment tag) {
		ChaCha20.chacha20(key, nonce, plaintext, ciphertext, 1);
		chacha20Poly1305Tag(key, nonce, aad, ciphertext, tag);
	}

	public static void poly1305AeadDecrypt(MemorySegment aad, MemorySegment key, MemorySegment nonce, MemorySegment ciphertext, MemorySegment plaintext, MemorySegment tag) throws AEADBadTagException {
		interface Holder {
			ThreadLocal<MemorySegment> EXPECTED_TAG = ThreadLocal.withInitial(() -> {
				var arena = Arena.global();
				return arena.allocate(16, 16);
			});
		}

		var expectedTag = Holder.EXPECTED_TAG.get();
		chacha20Poly1305Tag(key, nonce, aad, ciphertext, expectedTag);

		if (expectedTag.mismatch(tag) != -1) {
			throw new AEADBadTagException("Invalid tag (expected %s, got %s)".formatted(Arrays.toString(expectedTag.toArray(JAVA_BYTE)), Arrays.toString(tag.toArray(JAVA_BYTE))));
		}

		ChaCha20.chacha20(key, nonce, ciphertext, plaintext, 1);
	}

	public static void poly1305AeadDecrypt(MemorySegment key, MemorySegment nonce, MemorySegment ciphertext, MemorySegment plaintext, MemorySegment tag) throws AEADBadTagException {
		poly1305AeadDecrypt(null, key, nonce, ciphertext, plaintext, tag);
	}


	private static void chacha20Poly1305Tag(MemorySegment chacha20Key, MemorySegment nonce, MemorySegment aad, MemorySegment ciphertext, MemorySegment tag) {
		record Cache(MemorySegment chacha20State, MemorySegment poly1305Key, Poly1305 poly1305, MemorySegment lengthBuffer) {
			Cache(Arena arena) {
				this(arena.allocateArray(JAVA_INT, 16), arena.allocateArray(JAVA_BYTE, 64), new Poly1305(arena), arena.allocateArray(JAVA_LONG, 2));
			}

			static final ThreadLocal<Cache> CACHE = ThreadLocal.withInitial(() -> new Cache(Arena.global()));
			static final MemorySegment ZEROS = Arena.global().allocate(16).asReadOnly();
		}

		var cache = Cache.CACHE.get();

		poly1305ChaChaKeyGen(cache.chacha20State, chacha20Key, nonce, cache.poly1305Key);

		var poly1305 = cache.poly1305;
		poly1305.init(cache.poly1305Key.asSlice(0, 32));

		if (aad != null) {
			poly1305.update(aad);
			poly1305.update(Cache.ZEROS.asSlice(0, pad16(aad.byteSize())));
		}

		poly1305.update(ciphertext);
		poly1305.update(Cache.ZEROS.asSlice(0, pad16(ciphertext.byteSize())));

		cache.lengthBuffer.setAtIndex(JAVA_LONG, 0, aad == null ? 0 : aad.byteSize());
		cache.lengthBuffer.setAtIndex(JAVA_LONG, 1, ciphertext.byteSize());
		poly1305.update(cache.lengthBuffer);

		poly1305.finish(tag);
	}

	private static int pad16(long length) {
		return length % 16 == 0 ? 0 : (int) (16 - (length % 16));
	}
}
