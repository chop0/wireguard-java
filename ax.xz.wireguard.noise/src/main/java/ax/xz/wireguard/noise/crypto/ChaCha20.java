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
		CHACHA20_CIPHER$MH = MethodHandles.insertArguments(chachaCipher, 4, (int)20);

		// void chacha_block_keystream(uint32_t *state, uint8_t *dst, int nrounds)
		var chacha_block_keystreamDescriptor = FunctionDescriptor.ofVoid(
			ADDRESS.withTargetLayout(sequenceLayout(16, JAVA_INT)).withName("state"),
			ADDRESS.withTargetLayout(sequenceLayout(64, JAVA_BYTE)).withName("dst"),
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
		initializeState(MemorySegment.ofArray(key), MemorySegment.ofArray(nonce), state, counter);
	}

	static void initializeState(MemorySegment key, MemorySegment nonce, MemorySegment state, int counter) {
		if (state.byteSize() != 64) {
			throw new IllegalArgumentException("State size must be 64 bytes (is " + state.byteSize() + ")");
		}

		// Constants
		state.setAtIndex(JAVA_INT, 0, 0x61707865);
		state.setAtIndex(JAVA_INT, 1, 0x3320646e);
		state.setAtIndex(JAVA_INT, 2, 0x79622d32);
		state.setAtIndex(JAVA_INT, 3, 0x6b206574);

		// Key
		state.asSlice(16, 32).copyFrom(key);

		// Block counter
		state.setAtIndex(JAVA_INT, 12, counter);

		// Nonce
		state.asSlice(52, 12).copyFrom(nonce);
	}


	public static void chacha20Block(MemorySegment state, MemorySegment output, int counter) {
		try {
			state.setAtIndex(JAVA_INT, 12, counter);

			if (state.isNative() && output.isNative()) {
				chacha20BlockDirect(state, output);
			} else {
				try (var arena = Arena.ofConfined()) {
					var nativeState = arena.allocate(state.byteSize(), 16).copyFrom(state);
					var nativeOutput = arena.allocate(64, 16);

					chacha20BlockDirect(nativeState, nativeOutput);

					output.copyFrom(nativeOutput);
				}
			}
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	private static void chacha20BlockDirect(MemorySegment state, MemorySegment output) {
		try {
			CHACHA20_BLOCK_KEYSTREAM$MH.invokeExact(state.asSlice(0, sequenceLayout(16, JAVA_INT)), output.asSlice(0, sequenceLayout(64, JAVA_BYTE)));
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	private static final ThreadLocal<MemorySegment> STATE = ThreadLocal.withInitial(() -> Arena.ofConfined().allocate(16 * 4, 16));

	public static void chacha20(MemorySegment key, MemorySegment nonce, MemorySegment input, MemorySegment output, int counter) {
		var state = STATE.get();
		initializeState(key, nonce, state, counter);

		if (input.isNative() && output.isNative()) {
			chacha20Direct(input, output, state);
		} else {
			try (var arena = Arena.ofConfined()) {
				var nativeInput = arena.allocate(input.byteSize(), 16).copyFrom(input);
				var nativeOutput = arena.allocate(input.byteSize(), 16);

				chacha20Direct(nativeInput, nativeOutput, state);
				output.copyFrom(nativeOutput);
			}
		}
	}

	private static void chacha20Direct(MemorySegment input, MemorySegment output, MemorySegment state) {
		if (output.byteSize() < input.byteSize()) {
			throw new IllegalArgumentException("Output buffer must be at least as large as input buffer");
		}

		try {
			CHACHA20_CIPHER$MH.invokeExact(state, output.asSlice(0, input.byteSize()), input.asSlice(0, input.byteSize()), (int)input.byteSize());
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	public static void chacha20(byte[] key, byte[] nonce, MemorySegment input, MemorySegment output, int counter) {
		chacha20(MemorySegment.ofArray(key), MemorySegment.ofArray(nonce), input, output, counter);
	}
}
