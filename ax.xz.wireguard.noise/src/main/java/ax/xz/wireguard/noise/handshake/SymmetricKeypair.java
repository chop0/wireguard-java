package ax.xz.wireguard.noise.handshake;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.lang.ref.Cleaner;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305NonceSize;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
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

	private final Key sendJCEKey;
	private final Key receiveJCEKey;

	private volatile long sendCounter = 0;

	SymmetricKeypair(byte[] sendKeyBytes, byte[] receiveKeyBytes) {
		var keyArena = Arena.ofShared();

		var sendKey = keyArena.allocate(sendKeyBytes.length, 16).copyFrom(MemorySegment.ofArray(sendKeyBytes));
		var receiveKey = keyArena.allocate(receiveKeyBytes.length, 16).copyFrom(MemorySegment.ofArray(receiveKeyBytes));

		cleaner.register(this, () -> clean(sendKey, receiveKey, keyArena));

		this.keyArena = keyArena;

		this.sendKey = sendKey;
		this.receiveKey = receiveKey;

		this.sendJCEKey = new SecretKeySpec(sendKeyBytes, "ChaCha20");
		this.receiveJCEKey = new SecretKeySpec(receiveKeyBytes, "ChaCha20");
	}

	private static MemorySegment getNonceSegment(long nonce) {
		interface Holder {
			ThreadLocal<MemorySegment> NONCE = ThreadLocal.withInitial(() -> Arena.global().allocate(ChaChaPoly1305NonceSize, 4));
		}

		var nonceBytes = Holder.NONCE.get();
		nonceBytes.set(JAVA_LONG, 0, nonce);

		return nonceBytes;
	}

	private static byte[] getNonce(long nonce) {
		return getNonceSegment(nonce).toArray(JAVA_BYTE);
	}

	public long cipher(MemorySegment src, MemorySegment dst) {
		var counter = (long)SEND_COUNTER.getAndAdd(this, 1);

		// TODO: add an easy way to choose the cipher implementation
		try {
			var cipher = CIPHER.get();
			cipher.init(Cipher.ENCRYPT_MODE, sendJCEKey, new IvParameterSpec(getNonce(counter)));
			cipher.doFinal(src.asByteBuffer(), dst.asByteBuffer());
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
				 InvalidAlgorithmParameterException | ShortBufferException e) {
			throw new AssertionError(e);
		}

//		long textLength = src.byteSize();
//		var ciphertext = dst.asSlice(0, textLength);
//		var tag = dst.asSlice(textLength, 16);
//		ChaCha20Poly1305.poly1305AeadEncrypt(sendKey, getNonceSegment(counter), src, ciphertext, tag);

		return counter;
	}

	public void decipher(long counter, MemorySegment src, MemorySegment dst) {
		try {
			var cipher = CIPHER.get();
			cipher.init(Cipher.DECRYPT_MODE, receiveJCEKey, new IvParameterSpec(getNonce(counter)));
			cipher.doFinal(src.asByteBuffer(), dst.asByteBuffer());
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
				 InvalidAlgorithmParameterException | ShortBufferException e) {
			throw new AssertionError(e);
		}

//		long textLength = src.byteSize() - 16;
//		var ciphertext = src.asSlice(0, textLength);
//		var tag = src.asSlice(textLength, 16);
//		ChaCha20Poly1305.poly1305AeadDecrypt(receiveKey, getNonceSegment(counter), ciphertext, dst, tag);
	}

	private static void clean(MemorySegment sendKey, MemorySegment receiveKey, Arena arena) {
		sendKey.fill((byte)0);
		receiveKey.fill((byte)0);
		arena.close();
	}

	public void clean() {
		clean(sendKey, receiveKey, keyArena);
	}

	private static final ThreadLocal<Cipher> CIPHER = ThreadLocal.withInitial(SymmetricKeypair::getCipher);
	private static Cipher getCipher() {
		try {
			return Cipher.getInstance("ChaCha20-Poly1305");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new AssertionError(e);
		}
	}
}
