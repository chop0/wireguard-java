package ax.xz.wireguard.crypto;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Base64;

import java.util.Objects;

public record NoisePublicKey(byte[] data) implements Serializable {
	public static final int LENGTH = 32;

	public NoisePublicKey {
		Objects.requireNonNull(data);

		if (data.length != LENGTH) {
			throw new IllegalArgumentException("NoisePublicKey must be 32 bytes");
		}
	}

	public static NoisePublicKey fromBase64(String base64) {
		return new NoisePublicKey(Base64.getDecoder().decode(base64));
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(data);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof NoisePublicKey npk)) {
			return false;
		}
		return Arrays.equals(data, npk.data);
	}
}
