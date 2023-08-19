package ax.xz.wireguard.device;

import ax.xz.wireguard.crypto.keys.NoisePresharedKey;
import ax.xz.wireguard.crypto.keys.NoisePrivateKey;
import ax.xz.wireguard.crypto.keys.NoisePublicKey;

import java.net.InetSocketAddress;
import java.time.Duration;

@SuppressWarnings("unused")
public interface WireguardDeviceMBean {
	void addPeer(NoisePublicKey publicKey, NoisePresharedKey noisePresharedKey, Duration keepaliveInterval, InetSocketAddress endpoint);
	void deletePeer(NoisePublicKey peer);

	void broadcastTransport(byte[] data) throws InterruptedException;

	NoisePrivateKey getStaticIdentity();

	int getNumberOfPeers();
	int getNumberOfHandshakes();

	long getNumberOfBytesSent();
	long getNumberOfBytesReceived();
}
