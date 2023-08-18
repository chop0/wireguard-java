package ax.xz.wireguard;

import ax.xz.wireguard.crypto.NoisePublicKey;

import java.net.SocketAddress;

public interface PeerMBean {
	int getInboundQueueSize();

	int getDecryptedQueueSize();

	String getAuthority();
	NoisePublicKey getRemoteStatic();
}
