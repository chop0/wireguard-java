package ax.xz.wireguard.noise.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static java.nio.ByteOrder.LITTLE_ENDIAN;

public class Poly1305 {
	private static final MethodHandle POLY1305_CONSTRUCTOR, POLY1305_ENGINE_INIT, POLY1305_ENGINE_UPDATE, POLY1305_ENGINE_DO_FINAL;

	static {
		try {
			var poly1305Class = Class.forName("com.sun.crypto.provider.Poly1305");
			POLY1305_CONSTRUCTOR = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findConstructor(poly1305Class, MethodType.methodType(void.class));
			POLY1305_ENGINE_INIT = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findVirtual(poly1305Class, "engineInit", MethodType.methodType(void.class, Key.class, AlgorithmParameterSpec.class));
			POLY1305_ENGINE_UPDATE = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findVirtual(poly1305Class, "engineUpdate", MethodType.methodType(void.class, ByteBuffer.class));
			POLY1305_ENGINE_DO_FINAL = MethodHandles.privateLookupIn(poly1305Class, MethodHandles.lookup())
				.findVirtual(poly1305Class, "engineDoFinal", MethodType.methodType(byte[].class));
		} catch (NoSuchMethodException | IllegalAccessException | ClassNotFoundException e) {
			throw new RuntimeException(e);
		}
	}

	static byte[] poly1305(ByteBuffer message, byte[] key) {
		try {
			var poly1305 = POLY1305_CONSTRUCTOR.invoke();
			POLY1305_ENGINE_INIT.invoke(poly1305, (Key) new SecretKeySpec(key, "ChaCha20-Poly1305"), (AlgorithmParameterSpec) null);
			POLY1305_ENGINE_UPDATE.invoke(poly1305, message);
			return (byte[]) POLY1305_ENGINE_DO_FINAL.invoke(poly1305);
		} catch (Throwable throwable) {
			throw new RuntimeException(throwable);
		}
	}

	static void poly1305ChaChaKeyGen(byte[] key, byte[] nonce, byte[] output) {
		var state = new int[16];
		ChaCha20.initializeState(key, nonce, state, 0);
		var block = new byte[64];
		ChaCha20.chacha20Block(state, block);
		System.arraycopy(block, 0, output, 0, 32);
	}

	private static int pad16(int x) {
		if (x % 16 == 0) {
			return 0;
		} else {
			return 0 + 16 - (x % 16);
		}
	}

	/**
	 *       chacha20_aead_encrypt(aad, key, iv, constant, plaintext):
	 *          nonce = constant | iv
	 *          otk = poly1305_key_gen(key, nonce)
	 *          ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)
	 *          mac_data = aad | pad16(aad)
	 *          mac_data |= ciphertext | pad16(ciphertext)
	 *          mac_data |= num_to_4_le_bytes(aad.length)
	 *          mac_data |= num_to_4_le_bytes(ciphertext.length)
	 *          tag = poly1305_mac(mac_data, otk)
	 *          return (ciphertext, tag)
	 */
	public static void poly1305AeadEncrypt(byte[] aad, byte[] key, byte[] nonce, ByteBuffer plaintext, ByteBuffer ciphertext, ByteBuffer tag) {
		int aadLength = aad.length;

		ChaCha20.chacha20(key, nonce, plaintext,  ciphertext, 1);
		ciphertext.flip();

		int ciphertextLength = ciphertext.remaining();

		var macData = ByteBuffer.allocate(aadLength + pad16(aadLength) + ciphertextLength + pad16(ciphertextLength) + 8 + 8).order(LITTLE_ENDIAN);
		macData.put(aad);
		macData.position(macData.position() + pad16(aad.length));
		macData.put(ciphertext.duplicate());
		macData.position(macData.position() + pad16(ciphertextLength));
		macData.putLong(aad.length);
		macData.putLong(ciphertextLength);
		macData.flip();
//		printHex(ciphertext);

		var otk = new byte[32];
		poly1305ChaChaKeyGen(key, nonce, otk);
		byte[] tagOut = poly1305(macData, otk);
		tag.put(tagOut);
	}

	public static void poly1305AeadDecrypt(byte[] aad, byte[] key, byte[] nonce, ByteBuffer ciphertext, ByteBuffer plaintext, ByteBuffer tag) throws AEADBadTagException {
		int aadLength = aad.length;
		int ciphertextLength = ciphertext.remaining();

		var macData = ByteBuffer.allocate(aadLength + pad16(aadLength) + ciphertextLength + pad16(ciphertextLength) + 8 + 8).order(LITTLE_ENDIAN);
		macData.put(aad);
		macData.position(macData.position() + pad16(aad.length));
		macData.put(ciphertext.duplicate());
		macData.position(macData.position() + pad16(ciphertextLength));
		macData.putLong(aad.length);
		macData.putLong(ciphertextLength);
		macData.flip();
//		printHex(ciphertext);

		var otk = new byte[32];
		poly1305ChaChaKeyGen(key, nonce, otk);
		byte[] expectedTag = poly1305(macData, otk);

		byte[] tagBytes = new byte[16];
		tag.get(tagBytes);
		if (!Arrays.equals(expectedTag, tagBytes)) {
			throw new AEADBadTagException("Invalid tag (expected %s, got %s)".formatted(Arrays.toString(expectedTag), Arrays.toString(tagBytes)));
		}

		ChaCha20.chacha20(key, nonce, ciphertext, plaintext, 1);
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
}
