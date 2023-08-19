package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.crypto.keys.NoisePublicKey;

public interface PeerMBean {
	int getInboundQueueSize();

	int getDecryptedQueueSize();

	String getAuthority();
	NoisePublicKey getRemoteStatic();
}
