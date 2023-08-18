package ax.xz.wireguard;

import ax.xz.wireguard.crypto.NoisePresharedKey;
import ax.xz.wireguard.crypto.NoisePrivateKey;
import ax.xz.wireguard.crypto.NoisePublicKey;

import java.net.SocketAddress;
import java.time.Duration;

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
