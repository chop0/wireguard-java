package ax.xz.wireguard.noise.crypto;

import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Crypto {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

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
	public static void HMAC1(byte[] sum, byte[] key, byte[] in0) {
		var mac = new HMac(new Blake2sDigest(256));
		mac.init(new KeyParameter(key));
		mac.update(in0, 0, in0.length);
		mac.doFinal(sum, 0);
	}

	public static void HMAC2(byte[] sum, byte[] key, byte[] in0, byte[] in1) {
		var mac = new HMac(new Blake2sDigest(256));
		mac.init(new KeyParameter(key));
		mac.update(in0, 0, in0.length);
		mac.update(in1, 0, in1.length);
		mac.doFinal(sum, 0);
	}

	public static void KDF1(byte[] t0, byte[] key, byte[] input) {
		byte[] t1 = new byte[BLAKE2S_SIZE_256];
		HMAC1(t1, key, input);
		HMAC1(t1, t1, new byte[]{0x1});

		System.arraycopy(t1, 0, t0, 0, t0.length);
	}

	public static void KDF2(byte[] t0, byte[] t1, byte[] key, byte[] input) {
		byte[] prk = new byte[BLAKE2S_SIZE_256];
		HMAC1(prk, key, input);
		HMAC1(t0, prk, new byte[]{0x1});
		HMAC2(t1, prk, t0, new byte[]{0x2});
	}

	public static void KDF3(byte[] t0, byte[] t1, byte[] t2, byte[] key, byte[] input) {
		byte[] prk = new byte[BLAKE2S_SIZE_256];
		HMAC1(prk, key, input);
		HMAC1(t0, prk, new byte[]{0x1});
		HMAC2(t1, prk, t0, new byte[]{0x2});
		HMAC2(t2, prk, t1, new byte[]{0x3});
	}

	public static byte[] BLAKE2s256(byte[] data) {
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("BLAKE2s-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		return md.digest(data);
	}
}
