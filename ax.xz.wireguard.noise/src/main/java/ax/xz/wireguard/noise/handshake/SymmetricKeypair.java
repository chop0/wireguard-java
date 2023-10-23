package ax.xz.wireguard.noise.handshake;

import ax.xz.wireguard.noise.crypto.ChaCha20Poly1305;
import ax.xz.wireguard.noise.crypto.Poly1305;

import javax.crypto.*;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.AtomicLong;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305NonceSize;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

public final class SymmetricKeypair {
	private static final VarHandle SEND_COUNTER;

	static {
		try {
			SEND_COUNTER = MethodHandles.lookup().findVarHandle(SymmetricKeypair.class, "sendCounter", long.class);
		} catch (NoSuchFieldException | IllegalAccessException e) {
			throw new AssertionError(e);
		}
	}

	private static final Cleaner cleaner = Cleaner.create();

	private final Arena keyArena;
	private final MemorySegment sendKey;
	private final MemorySegment receiveKey;

	private volatile long sendCounter = 0;

	SymmetricKeypair(byte[] sendKeyBytes, byte[] receiveKeyBytes) {
		var keyArena = Arena.ofShared();

		var sendKey = keyArena.allocate(sendKeyBytes.length, 16).copyFrom(MemorySegment.ofArray(sendKeyBytes));
		var receiveKey = keyArena.allocate(receiveKeyBytes.length, 16).copyFrom(MemorySegment.ofArray(receiveKeyBytes));

		cleaner.register(this, () -> clean(sendKey, receiveKey, keyArena));

		this.keyArena = keyArena;
		this.sendKey = sendKey;
		this.receiveKey = receiveKey;
	}

	private static MemorySegment getNonceBytes(long nonce) {
		interface Holder {
			ThreadLocal<MemorySegment> NONCE = ThreadLocal.withInitial(() -> Arena.global().allocate(ChaChaPoly1305NonceSize, 4));
		}

		var nonceBytes = Holder.NONCE.get();
		nonceBytes.set(JAVA_LONG, 0, nonce);

		return nonceBytes;
	}

	public long cipher(MemorySegment src, MemorySegment dst) {
		var counter = (long)SEND_COUNTER.getAndAdd(this, 1);

		long textLength = src.byteSize();

		var ciphertext = dst.asSlice(0, textLength);
		var tag = dst.asSlice(textLength, 16);

		ChaCha20Poly1305.poly1305AeadEncrypt(sendKey, getNonceBytes(counter), src, ciphertext, tag);

		return counter;
	}

	public void decipher(long counter, MemorySegment src, MemorySegment dst) throws BadPaddingException {
		long textLength = src.byteSize() - 16;

		var ciphertext = src.asSlice(0, textLength);
		var tag = src.asSlice(textLength, 16);

		ChaCha20Poly1305.poly1305AeadDecrypt(receiveKey, getNonceBytes(counter), ciphertext, dst, tag);
	}

	private static void clean(MemorySegment sendKey, MemorySegment receiveKey, Arena arena) {
		sendKey.fill((byte)0);
		receiveKey.fill((byte)0);
		arena.close();
	}

	public void clean() {
		clean(sendKey, receiveKey, keyArena);
	}
}
