package ax.xz.wireguard;

import ax.xz.wireguard.crypto.keys.NoisePrivateKey;

public interface WireguardDeviceMBean {
	void deletePeer(Peer peer);

	void broadcastTransport(byte[] data) throws InterruptedException;
	void setPeerSessionIndex(Peer peer, int sessionIndex);

	void clearSessionIndex(int sessionIndex);

	NoisePrivateKey getStaticIdentity();

	int getNumberOfPeers();
	int getNumberOfHandshakes();

	long getNumberOfBytesSent();
	long getNumberOfBytesReceived();
}
