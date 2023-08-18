package ax.xz.wireguard.crypto;

import java.util.Base64;
import java.util.Objects;

public record NoisePresharedKey(byte[] data) {
	public static final int LENGTH = 32;

	public NoisePresharedKey {
		Objects.requireNonNull(data);

		if (data.length != LENGTH) {
			throw new IllegalArgumentException("NoisePublicKey must be 32 bytes");
		}
	}

	public static NoisePresharedKey fromBase64(String base64) {
		return new NoisePresharedKey(Base64.getDecoder().decode(base64));
	}
}
