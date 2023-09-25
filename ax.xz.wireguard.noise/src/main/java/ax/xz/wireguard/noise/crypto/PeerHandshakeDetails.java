package ax.xz.wireguard.noise.crypto;

import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import static java.util.Objects.requireNonNull;

public record PeerHandshakeDetails(NoisePrivateKey localIdentity, NoisePublicKey remoteKey, NoisePresharedKey presharedKey) {
	public PeerHandshakeDetails {
		requireNonNull(localIdentity);
		requireNonNull(remoteKey);
		requireNonNull(presharedKey);
	}

	public static PeerHandshakeDetails of(NoisePrivateKey localIdentity, NoisePublicKey remoteKey) {
		return new PeerHandshakeDetails(localIdentity, remoteKey, NoisePresharedKey.zero());
	}
}
