package ax.xz.wireguard.noise.crypto;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Crypto {
	public static final int POLY1305_TAG_SIZE = 16;
	public static final int TIMESTAMP_LENGTH = 12;
	public static final int POLY1305_NONCE_SIZE = 24;
	public static final int BLAKE2S_SIZE_256 = 32;
	public static final int BLAKE2S_SIZE_128 = 16;
	public static final int TauSize = 32;

	/**
	 * TAI64N(): TAI64N timestamp of current time which is 12 bytes
	 */
	public static byte[] TAI64N() {
		var result = new byte[12];
		var time = System.currentTimeMillis() * 1000 + 4611686018427387914L;
		for (int i = 11; i >= 0; i--) {
			result[i] = (byte) (time & 0xFF);
			time >>= 8;
		}
		return result;
	}

	private static final int BLAKE2S_BLOCKBYTES = 64; // Define this constant

	private static final byte[] ipad = new byte[BLAKE2S_BLOCKBYTES];
	private static final byte[] opad = new byte[BLAKE2S_BLOCKBYTES];

	static {
		Arrays.fill(ipad, (byte) 0x36);
		Arrays.fill(opad, (byte) 0x5c);
	}

	public static void HMAC(byte[] sum, byte[] key, byte[]... messages) {
		byte[] K;
		if (key.length > BLAKE2S_BLOCKBYTES) {
			K = Crypto.BLAKE2s256(key);
		} else {
			K = key;
		}

		byte[] paddedK = new byte[BLAKE2S_BLOCKBYTES];
		System.arraycopy(K, 0, paddedK, 0, K.length);

		byte[] iKeyPad = new byte[BLAKE2S_BLOCKBYTES];
		byte[] oKeyPad = new byte[BLAKE2S_BLOCKBYTES];

		for (int i = 0; i < BLAKE2S_BLOCKBYTES; i++) {
			iKeyPad[i] = (byte) (paddedK[i] ^ ipad[i]);
			oKeyPad[i] = (byte) (paddedK[i] ^ opad[i]);
		}

		var b2s = getBlake2s256();
		b2s.update(iKeyPad);
		for (var message : messages)
			b2s.update(message);
		byte[] innerHash = b2s.digest();

		b2s.update(oKeyPad);
		b2s.update(innerHash);
		try {
			b2s.digest(sum, 0, sum.length);
		} catch (DigestException e) {
			throw new RuntimeException(e);
		}
	}


	public static void KDF1(byte[] t0, byte[] key, byte[] input) {
		byte[] t1 = new byte[BLAKE2S_SIZE_256];
		HMAC(t1, key, input);
		HMAC(t1, t1, new byte[]{0x1});

		System.arraycopy(t1, 0, t0, 0, t0.length);
	}

	public static void KDF2(byte[] t0, byte[] t1, byte[] key, byte[] input) {
		byte[] prk = new byte[BLAKE2S_SIZE_256];
		HMAC(prk, key, input);
		HMAC(t0, prk, new byte[]{0x1});
		HMAC(t1, prk, t0, new byte[]{0x2});
	}

	public static void KDF3(byte[] t0, byte[] t1, byte[] t2, byte[] key, byte[] input) {
		byte[] prk = new byte[BLAKE2S_SIZE_256];
		HMAC(prk, key, input);
		HMAC(t0, prk, new byte[]{0x1});
		HMAC(t1, prk, t0, new byte[]{0x2});
		HMAC(t2, prk, t1, new byte[]{0x3});
	}

	public static byte[] BLAKE2s256(byte[]... data) {
		var md = getBlake2s256();

		for (byte[] datum : data) {
			md.update(datum);
		}
		return md.digest();
	}

	public static MessageDigest getBlake2s256() {
		return new Blake2s(32);
	}
}
