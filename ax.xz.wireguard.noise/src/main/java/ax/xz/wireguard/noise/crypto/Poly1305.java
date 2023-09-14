package ax.xz.wireguard.noise.crypto;

import javax.crypto.AEADBadTagException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static java.lang.foreign.MemoryLayout.sequenceLayout;
import static java.lang.foreign.ValueLayout.*;
import static java.nio.ByteOrder.LITTLE_ENDIAN;

public class Poly1305 {
	static final MethodHandle poly1305_auth$MH;

	private static final ThreadLocal<MemorySegment> POLY1305_MAC = ThreadLocal.withInitial(() -> {
		var arena = Arena.global();
		return arena.allocate(16);
	});

	private static final ThreadLocal<MemorySegment> POLY1305_KEY = ThreadLocal.withInitial(() -> {
		var arena = Arena.global();
		return arena.allocate(32);
	});

	static {
		System.loadLibrary("poly1305-donna");
		var symbols = SymbolLookup.loaderLookup();
		var linker = Linker.nativeLinker();

		var descriptor = FunctionDescriptor.ofVoid(
			ADDRESS.withTargetLayout(sequenceLayout(16, JAVA_BYTE)).withName("mac"),
			ADDRESS.withTargetLayout(sequenceLayout(JAVA_BYTE)).withName("m"),
			JAVA_LONG.withName("bytes"),
			ADDRESS.withTargetLayout(sequenceLayout(32, JAVA_BYTE)).withName("key")
		);

		poly1305_auth$MH = symbols.find("poly1305_auth").map(addr -> linker.downcallHandle(addr, descriptor)).orElseThrow();
	}

	static byte[] poly1305(ByteBuffer message_, ByteBuffer key_) {
		boolean needsAllocation = !(message_.isDirect() && key_.isDirect());
		if (needsAllocation) {
			return poly1305Copy(message_, key_);
		} else {
			return poly1305Direct(MemorySegment.ofBuffer(message_), MemorySegment.ofBuffer(key_));
		}
	}

	private static byte[] poly1305Copy(ByteBuffer message_, ByteBuffer key_) {
		try (var arena = Arena.ofConfined()) {
			MemorySegment message;
			if (message_.isDirect()) {
				message = MemorySegment.ofBuffer(message_);
			} else {
				message = arena.allocate(message_.remaining());
				message.asByteBuffer().put(message_);
			}

			MemorySegment key;
			if (key_.isDirect()) {
				key = MemorySegment.ofBuffer(key_);
			} else {
				key = POLY1305_KEY.get();
				key.asByteBuffer().put(key_);
			}

			return poly1305Direct(message, key);
		}
	}

	private static byte[] poly1305Direct(MemorySegment message, MemorySegment key) {
		var mac = POLY1305_MAC.get();

		try {
			poly1305_auth$MH.invokeExact(mac, message, message.byteSize(), key);
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
		return mac.toArray(JAVA_BYTE);
	}

	static void poly1305ChaChaKeyGen(byte[] key, byte[] nonce, ByteBuffer output) {
		var state = new int[16];
		ChaCha20.initializeState(key, nonce, state, 0);
		var block = new byte[64];
		ChaCha20.chacha20Block(state, block);
		output.put(block, 0, 32);
	}

	private static int pad16(int x) {
		if (x % 16 == 0) {
			return 0;
		} else {
			return 0 + 16 - (x % 16);
		}
	}

	private static final ThreadLocal<ByteBuffer> OTK = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(32));
	public static void poly1305AeadEncrypt(ByteBuffer scratchBuffer, byte[] aad, byte[] key, byte[] nonce, ByteBuffer plaintext, ByteBuffer ciphertext, ByteBuffer tag) {
		int aadLength = aad.length;

		ChaCha20.chacha20(key, nonce, plaintext, ciphertext, 1);
		ciphertext.flip();
		int ciphertextLength = ciphertext.remaining();

		var macData = buildMacData(scratchBuffer, aad, ciphertext, aadLength, ciphertextLength);

		var otk = OTK.get().clear();
		poly1305ChaChaKeyGen(key, nonce, otk);
		otk.flip();

		byte[] tagOut = poly1305(macData, otk);
		tag.put(tagOut);
	}

	public static void poly1305AeadEncrypt(byte[] aad, byte[] key, byte[] nonce, ByteBuffer plaintext, ByteBuffer ciphertext, ByteBuffer tag) {
		poly1305AeadEncrypt(ByteBuffer.allocateDirect(poly1305AeadBufferSize(aad.length, plaintext.remaining())), aad, key, nonce, plaintext, ciphertext, tag);
	}

	private static ByteBuffer buildMacData(ByteBuffer scratchBuffer, byte[] aad, ByteBuffer ciphertext, int aadLength, int ciphertextLength) {
		if (scratchBuffer.capacity() < poly1305AeadBufferSize(aadLength, ciphertextLength))
			throw new IllegalArgumentException("scratchBuffer is too small");

		var macData = scratchBuffer.clear().order(LITTLE_ENDIAN);
		macData.put(aad);

		for (int i = 0; i < pad16(aadLength); i++) {
			macData.put((byte) 0);
		}

		macData.put(ciphertext.duplicate());
		for (int i = 0; i < pad16(ciphertextLength); i++) {
			macData.put((byte) 0);
		}

		macData.putLong(aad.length);
		macData.putLong(ciphertextLength);
		macData.flip();
		return macData;
	}

	public static void poly1305AeadDecrypt(ByteBuffer scratchBuffer, byte[] aad, byte[] key, byte[] nonce, ByteBuffer ciphertext, ByteBuffer plaintext, ByteBuffer tag) throws AEADBadTagException {
		int aadLength = aad.length;
		int ciphertextLength = ciphertext.remaining();

		var macData = buildMacData(scratchBuffer, aad, ciphertext, aadLength, ciphertextLength);

		var otk = OTK.get().clear();
		poly1305ChaChaKeyGen(key, nonce, otk);
		otk.flip();

		byte[] expectedTag = poly1305(macData, otk);

		byte[] tagBytes = new byte[16];
		tag.get(tagBytes);
		if (!Arrays.equals(expectedTag, tagBytes)) {
			throw new AEADBadTagException("Invalid tag (expected %s, got %s)".formatted(Arrays.toString(expectedTag), Arrays.toString(tagBytes)));
		}

		ChaCha20.chacha20(key, nonce, ciphertext, plaintext, 1);
	}

	public static void poly1305AeadDecrypt(byte[] aad, byte[] key, byte[] nonce, ByteBuffer ciphertext, ByteBuffer plaintext, ByteBuffer tag) throws AEADBadTagException {
		poly1305AeadDecrypt(ByteBuffer.allocateDirect(poly1305AeadBufferSize(aad.length, ciphertext.remaining())), aad, key, nonce, ciphertext, plaintext, tag);
	}

	private static void printHex(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			byte b = bytes[i];
			System.out.printf("%02x ", b);
			if (i % 16 == 15) {
				System.out.println();
			}
		}
		System.out.println();
	}

	private static void printHex(ByteBuffer bytes) {
		bytes = bytes.duplicate();
		System.out.println("Printing hex");
		for (int i = 0; i < bytes.remaining(); i++) {
			byte b = bytes.get(i);
			System.out.printf("%02x ", b);
			if (i % 16 == 15) {
				System.out.println();
			}
		}
		System.out.println();
	}

	public static int poly1305AeadBufferSize(int aadLength, int plaintextLength) {
		return aadLength + pad16(aadLength) + plaintextLength + pad16(plaintextLength) + 8 + 8;
	}
}
