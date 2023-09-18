package ax.xz.wireguard.noise.crypto;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;

import static java.lang.foreign.MemoryLayout.sequenceLayout;
import static java.lang.foreign.ValueLayout.*;

public class ChaCha20 {
	private static final MethodHandle CHACHA20_CIPHER$MH;
	private static final MethodHandle CHACHA20_BLOCK_KEYSTREAM$MH;

	static {
		System.loadLibrary("chacha");

		var symbols = SymbolLookup.loaderLookup();
		var linker = Linker.nativeLinker();

		// void chacha_cipher(uint32_t *state, uint8_t *dst, const uint8_t *src,
		//			  unsigned int bytes, int nrounds)
		var chacha_cipherDescriptor = FunctionDescriptor.ofVoid(
			ADDRESS.withTargetLayout(sequenceLayout(4, JAVA_INT)).withName("state"),
			ADDRESS.withTargetLayout(sequenceLayout(JAVA_BYTE)).withName("dst"),
			ADDRESS.withTargetLayout(sequenceLayout(JAVA_BYTE)).withName("src"),
			JAVA_INT.withName("bytes"),
			JAVA_INT.withName("nrounds")
		);

		var chachaCipher = symbols.find("chacha_cipher").map(addr -> linker.downcallHandle(addr, chacha_cipherDescriptor)).orElseThrow();
		CHACHA20_CIPHER$MH = MethodHandles.insertArguments(chachaCipher, 4, 20);

		// void chacha_block_keystream(uint32_t *state, uint8_t *dst, int nrounds)
		var chacha_block_keystreamDescriptor = FunctionDescriptor.ofVoid(
			ADDRESS.withTargetLayout(sequenceLayout(4, JAVA_INT)).withName("state"),
			ADDRESS.withTargetLayout(sequenceLayout(JAVA_BYTE)).withName("dst"),
			JAVA_INT.withName("nrounds")
		);

		var chachaBlockKeystream = symbols.find("chacha_block_keystream").map(addr -> linker.downcallHandle(addr, chacha_block_keystreamDescriptor)).orElseThrow();
		CHACHA20_BLOCK_KEYSTREAM$MH = MethodHandles.insertArguments(chachaBlockKeystream, 2, 20);
	}


	// Method to initialize the state matrix
	static void initializeState(byte[] key, byte[] nonce, MemorySegment state, int counter) {
		if (state.byteSize() != 64) {
			throw new IllegalArgumentException("State size must be 64 bytes (is " + state.byteSize() + ")");
		}

		// Constants
		state.setAtIndex(JAVA_INT, 0, 0x61707865);
		state.setAtIndex(JAVA_INT, 1, 0x3320646e);
		state.setAtIndex(JAVA_INT, 2, 0x79622d32);
		state.setAtIndex(JAVA_INT, 3, 0x6b206574);

		// Key
		for (int i = 0; i < 8; i++) {
			state.setAtIndex(JAVA_INT, 4 + i, byteArrayToIntLittleEndian(key, i * 4));
		}

		// Block counter
		state.setAtIndex(JAVA_INT, 12, counter);

		// Nonce
		state.setAtIndex(JAVA_INT, 13, byteArrayToIntLittleEndian(nonce, 0));
		state.setAtIndex(JAVA_INT, 14, byteArrayToIntLittleEndian(nonce, 4));
		state.setAtIndex(JAVA_INT, 15, byteArrayToIntLittleEndian(nonce, 8));
	}

	static int byteArrayToIntLittleEndian(byte[] b, int offset) {
		return (b[offset] & 0xFF) |
			   ((b[offset + 1] & 0xFF) << 8) |
			   ((b[offset + 2] & 0xFF) << 16) |
			   ((b[offset + 3] & 0xFF) << 24);
	}


	public static void chacha20Block(MemorySegment state, MemorySegment output, int counter) {
		try {
			state.setAtIndex(JAVA_INT, 12, counter);
			CHACHA20_BLOCK_KEYSTREAM$MH.invokeExact(state, output);
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	private static final ThreadLocal<MemorySegment> STATE = ThreadLocal.withInitial(() -> Arena.ofConfined().allocate(16 * 4, 16));
	public static void chacha20(byte[] key, byte[] nonce, MemorySegment input, MemorySegment output, int counter) {
		var state = STATE.get();
		initializeState(key, nonce, state, counter);

		try {
			CHACHA20_CIPHER$MH.invokeExact(state, output, input, (int)input.byteSize());
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}
}
