package ax.xz.wireguard;

import ax.xz.wireguard.crypto.keys.NoisePublicKey;

public interface PeerMBean {
	int getInboundQueueSize();

	int getDecryptedQueueSize();

	String getAuthority();
	NoisePublicKey getRemoteStatic();
}
