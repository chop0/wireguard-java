package ax.xz.wireguard.noise.crypto;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.MemoryLayout.sequenceLayout;
import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.ValueLayout.*;

public class NativePoly1305 implements Poly1305 {
	static final MethodHandle poly1305_init$MH, poly1305_update$MH, poly1305_finish$MH, poly1305_power_on_self_test$MH;

	/**
	 * typedef struct poly1305_context {
	 * size_t aligner;
	 * unsigned char opaque[136];
	 * } poly1305_context;
	 */
	 static final StructLayout POLY1305_CONTEXT = structLayout(
		JAVA_LONG.withName("aligner"),
		sequenceLayout(136, JAVA_BYTE).withName("opaque")
	);

	static {
		System.loadLibrary("poly1305-donna");

		var symbols = SymbolLookup.loaderLookup();
		var linker = Linker.nativeLinker();

		/**
		 * void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
		 * void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
		 * void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);
		 *
		 * int poly1305_power_on_self_test(void);
		 */
		poly1305_init$MH = linker.downcallHandle(
			symbols.find("poly1305_init").orElseThrow(),
			FunctionDescriptor.ofVoid(
				ADDRESS.withTargetLayout(POLY1305_CONTEXT).withName("ctx"),
				ADDRESS.withTargetLayout(sequenceLayout(32, JAVA_BYTE))
			)
		);

		poly1305_update$MH = linker.downcallHandle(
			symbols.find("poly1305_update").orElseThrow(),
			FunctionDescriptor.ofVoid(
				ADDRESS.withTargetLayout(POLY1305_CONTEXT).withName("ctx"),
				ADDRESS.withTargetLayout(sequenceLayout(JAVA_BYTE)).withName("m"),
				JAVA_LONG.withName("bytes")
			)
		);

		poly1305_finish$MH = linker.downcallHandle(
			symbols.find("poly1305_finish").orElseThrow(),
			FunctionDescriptor.ofVoid(
				ADDRESS.withTargetLayout(POLY1305_CONTEXT).withName("ctx"),
				ADDRESS.withTargetLayout(sequenceLayout(16, JAVA_BYTE)).withName("mac")
			)
		);

		poly1305_power_on_self_test$MH = linker.downcallHandle(
			symbols.find("poly1305_power_on_self_test").orElseThrow(),
			FunctionDescriptor.of(JAVA_INT)
		);

		boolean selfTestResult;
		try {
			selfTestResult = ((int) poly1305_power_on_self_test$MH.invokeExact() != 1);
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}

		if (selfTestResult) {
			throw new ExceptionInInitializerError("Poly1305 self-test failed");
		}
	}

	private final MemorySegment context;
	private boolean finished = false, initialised = false;

	NativePoly1305(Arena arena) {
		this(arena.allocate(POLY1305_CONTEXT));
	}

	NativePoly1305(MemorySegment context) {
		this.context = context;
	}

	public NativePoly1305() {
		this(Arena.ofAuto());
	}

	@Override
	public void init(MemorySegment key) {
		Arena arena = null;
		if (!key.isNative()) {
			arena = Arena.ofConfined();
			key = arena.allocate(key.byteSize(), 1).copyFrom(key);
		}

		try {
			poly1305_init$MH.invokeExact(context, key);
		} catch (Throwable e) {
			throw new RuntimeException(e);
		} finally {
			if (arena != null)
				arena.close();
		}
		initialised = true;
		finished = false;
	}

	@Override
	public void update(MemorySegment message) {
		if (finished) {
			throw new IllegalStateException("Poly1305 context has already been finished");
		}
		if (!initialised) {
			throw new IllegalStateException("Poly1305 context has not been initialised");
		}

		Arena arena = null;
		if (!message.isNative()) {
			arena = Arena.ofConfined();
			message = arena.allocate(message.byteSize(), 1).copyFrom(message);
		}

		try {
			poly1305_update$MH.invokeExact(context, message, message.byteSize());
		} catch (Throwable e) {
			throw new RuntimeException(e);
		} finally {
			if (arena != null)
				arena.close();
		}
	}

	@Override
	public void finish(MemorySegment mac) {
		if (finished) {
			throw new IllegalStateException("Poly1305 context has already been finished");
		}
		if (!initialised) {
			throw new IllegalStateException("Poly1305 context has not been initialised");
		}

		Arena arena = null;
		MemorySegment nativeMac = null;
		if (!mac.isNative()) {
			arena = Arena.ofConfined();
			nativeMac = arena.allocate(mac.byteSize(), 1);
		}

		try {
			if (nativeMac != null) {
				poly1305_finish$MH.invokeExact(context, nativeMac);
				mac.copyFrom(nativeMac);
			} else {
				poly1305_finish$MH.invokeExact(context, mac);
			}
		} catch (Throwable e) {
			throw new RuntimeException(e);
		} finally {
			if (arena != null)
				arena.close();
		}
		finished = true;
	}

	@Override
	public byte[] finish() {
		try (var arena = Arena.ofConfined()) {
			var mac = arena.allocate(16, 1);
			finish(mac);
			return mac.toArray(JAVA_BYTE);
		}
	}
}
