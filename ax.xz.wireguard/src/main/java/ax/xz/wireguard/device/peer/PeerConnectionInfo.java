package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.noise.crypto.PeerHandshakeDetails;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.IPFilter;

import javax.annotation.Nullable;
import java.net.InetSocketAddress;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

public record PeerConnectionInfo(
	PeerHandshakeDetails handshakeDetails,

	@Nullable InetSocketAddress endpoint,
	Duration keepaliveInterval,

	IPFilter filter
) {
	public PeerConnectionInfo {
		requireNonNull(handshakeDetails);

		if (keepaliveInterval == null)
			keepaliveInterval = Duration.ofDays(1_000_000_000);
	}

	public static PeerConnectionInfo of(NoisePrivateKey localIdentity, NoisePublicKey remoteStatic) {
		return new PeerConnectionInfo(
			PeerHandshakeDetails.of(localIdentity, remoteStatic),
			null,
			Duration.ofDays(1_000_000_000),
			IPFilter.allowingAll()
		);
	}

	public boolean canInitiateHandshake() {
		return endpoint != null;
	}

	@Override
	public String toString() {
		if (endpoint != null)
			return endpoint.toString();
		else
			return handshakeDetails.remoteKey().toString();
	}
}
