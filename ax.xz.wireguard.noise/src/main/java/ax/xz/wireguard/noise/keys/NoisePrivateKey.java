package ax.xz.wireguard.noise.keys;

import ax.xz.wireguard.noise.crypto.internal.X25519;

import java.io.Serializable;
import java.lang.ref.Cleaner;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

public record NoisePrivateKey(byte[] data, NoisePublicKey publicKey) implements Serializable {
	private static final Cleaner CLEANER = Cleaner.create();

	public static final int LENGTH = 32;

	public NoisePrivateKey {
		Objects.requireNonNull(data);
		Objects.requireNonNull(publicKey);

		if (data.length != LENGTH) {
			throw new IllegalArgumentException("NoisePrivateKey must be 32 bytes");
		}

		CLEANER.register(this, () -> {
			Arrays.fill(data, (byte) 0);
		});
	}

	NoisePrivateKey(byte[] data) {
		this(data, new NoisePublicKey(getPublicKey(data)));
	}

	private static byte[] getPublicKey(byte[] privateKey) {
		byte[] publicKey = new byte[NoisePublicKey.LENGTH];
		X25519.generatePublicKey(privateKey, 0, publicKey, 0);
		return publicKey;
	}

	public static NoisePrivateKey newPrivateKey() {
		var secureRandom = new SecureRandom();
		byte[] pk = new byte[LENGTH];

		X25519.generatePrivateKey(secureRandom, pk);
		return new NoisePrivateKey(pk);
	}

	public NoisePublicKey sharedSecret(NoisePublicKey publicKey) {
		byte[] sharedSecret = new byte[NoisePublicKey.LENGTH];
		X25519.calculateAgreement(data, 0, publicKey.data(), 0, sharedSecret, 0);
		return new NoisePublicKey(sharedSecret);
	}

	public static NoisePrivateKey fromBase64(String base64) {
		return new NoisePrivateKey(Base64.getDecoder().decode(base64));
	}
}
