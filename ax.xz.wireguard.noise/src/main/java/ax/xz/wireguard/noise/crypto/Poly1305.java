package ax.xz.wireguard.noise.crypto;

import javax.crypto.AEADBadTagException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.ValueLayout.*;
import static java.nio.ByteOrder.LITTLE_ENDIAN;

public class Poly1305 {
	static final MethodHandle poly1305_auth$MH;

	private static final ThreadLocal<MemorySegment> POLY1305_MAC = ThreadLocal.withInitial(() -> {
		var arena = Arena.global();
		return arena.allocate(16, 16);
	});

	private static final ThreadLocal<MemorySegment> POLY1305_KEY = ThreadLocal.withInitial(() -> {
		var arena = Arena.global();
		return arena.allocate(32, 16);
	});

	private static final ThreadLocal<MemorySegment> POLY1305_CHACHA_BLOCK = ThreadLocal.withInitial(() -> {
		var arena = Arena.global();
		return arena.allocate(64, 16);
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
		var block = POLY1305_CHACHA_BLOCK.get();
		ChaCha20.chacha20Block(state, block, 0);
		MemorySegment.ofBuffer(output.order(LITTLE_ENDIAN)).copyFrom(block.asSlice(0, 32));
	}


	private static final ThreadLocal<ByteBuffer> OTK = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(32));

	public static void poly1305AeadEncrypt(MemorySegment scratchBuffer, byte[] aad, byte[] key, byte[] nonce, MemorySegment plaintext, MemorySegment ciphertext, MemorySegment tag) {
		ChaCha20.chacha20(key, nonce, plaintext, ciphertext, 1);
		var macData = buildMacData(scratchBuffer, aad, ciphertext);
//		System.out.println("encrypt");
//		hexPrint(macData);

		var otk = OTK.get().clear();
		poly1305ChaChaKeyGen(key, nonce, otk);
		otk.flip();

		byte[] tagOut = poly1305(macData.asByteBuffer(), otk);
		tag.copyFrom(MemorySegment.ofArray(tagOut));
	}

	public static void poly1305AeadEncrypt(byte[] aad, byte[] key, byte[] nonce, ByteBuffer plaintext, ByteBuffer ciphertext, ByteBuffer tag) {
		try (var arena = Arena.ofConfined()) {
			poly1305AeadEncrypt(arena.allocate(poly1305AeadBufferSize(aad.length, plaintext.remaining())), aad, key, nonce, MemorySegment.ofBuffer(plaintext), MemorySegment.ofBuffer(ciphertext), MemorySegment.ofBuffer(tag));
		}
	}

	private static MemorySegment buildMacData(MemorySegment buffer, byte[] aad, MemorySegment ciphertext) {
		long aadLength = aad.length;
		long ciphertextLength = ciphertext.byteSize();

		int aadPadding = pad16(aadLength);
		int ciphertextPadding = pad16(ciphertextLength);

		if (buffer.byteSize() < aadLength + aadPadding + ciphertextLength + ciphertextPadding + 8 + 8)
			throw new IllegalArgumentException("scratchBuffer is too small");

		long aadOffset = 0;
		long ciphertextOffset = aadLength + aadPadding;

		long aadLengthOffset = ciphertextOffset + ciphertextLength + ciphertextPadding;
		long ciphertextLengthOffset = aadLengthOffset + 8;

		buffer.asSlice(aadOffset, aadLength).copyFrom(MemorySegment.ofArray(aad));
		buffer.asSlice(aadOffset + aadLength, aadPadding).fill((byte)0);
		buffer.asSlice(ciphertextOffset, ciphertextLength).copyFrom(ciphertext);
		buffer.asSlice(ciphertextOffset + ciphertextLength, ciphertextPadding).fill((byte)0);

		buffer.set(JAVA_LONG, aadLengthOffset, aadLength);
		buffer.set(JAVA_LONG, ciphertextLengthOffset, ciphertextLength);

		return buffer.asSlice(0, aadLength + aadPadding + ciphertextLength + ciphertextPadding + 8 + 8);
	}

	public static void poly1305AeadDecrypt(MemorySegment scratchBuffer, byte[] aad, byte[] key, byte[] nonce, MemorySegment ciphertext, MemorySegment plaintext, MemorySegment tag) throws AEADBadTagException {
		var macData = buildMacData(scratchBuffer, aad, ciphertext);
//		System.out.println("decrypt");
//		hexPrint(macData);

		var otk = OTK.get().clear();
		poly1305ChaChaKeyGen(key, nonce, otk);
		otk.flip();

		byte[] expectedTag = poly1305(macData.asByteBuffer(), otk);

		byte[] tagBytes = new byte[16];
		MemorySegment.ofArray(tagBytes).copyFrom(tag);
		if (!Arrays.equals(expectedTag, tagBytes)) {
			throw new AEADBadTagException("Invalid tag (expected %s, got %s)".formatted(Arrays.toString(expectedTag), Arrays.toString(tagBytes)));
		}

		ChaCha20.chacha20(key, nonce, ciphertext, plaintext, 1);
	}

	private static final void hexPrint(MemorySegment segment) {
		for (int i = 0; i < segment.byteSize(); i++) {
			System.out.printf("%02x ", segment.get(JAVA_BYTE, i));
			if (i % 16 == 15) {
				System.out.println();
			}
		}
		System.out.println();
	}

	public static void poly1305AeadDecrypt(byte[] aad, byte[] key, byte[] nonce, MemorySegment ciphertext, MemorySegment plaintext, MemorySegment tag) throws AEADBadTagException {
		try (var arena = Arena.ofConfined()) {
			poly1305AeadDecrypt(arena.allocate(poly1305AeadBufferSize(aad.length, ciphertext.byteSize())), aad, key, nonce, ciphertext, plaintext, tag);
		}
	}

	public static int poly1305AeadBufferSize(long aadLength, long plaintextLength) {
		return (int) (aadLength + pad16(aadLength) + plaintextLength + pad16(plaintextLength) + 8 + 8);
	}

	private static int pad16(long length) {
		return length % 16 == 0 ? 0 : (int) (16 - (length % 16));
	}
}
