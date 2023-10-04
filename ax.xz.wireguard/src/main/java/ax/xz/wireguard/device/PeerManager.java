package ax.xz.wireguard.device;

import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.device.peer.PeerConnectionInfo;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.spi.WireguardRouter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PeerManager implements AutoCloseable {
	private final Map<NoisePublicKey, PeerConnectionInfo> peerConnectionInfo = new ConcurrentHashMap<>();
	private final Map<NoisePublicKey, Peer> peers = new ConcurrentHashMap<>();

	private final NoisePrivateKey localIdentity;

	private final WireguardRouter peerRouter;
	private final TunPacketRouter tpr;

	public PeerManager(NoisePrivateKey localIdentity, WireguardRouter peerRouter, TunPacketRouter tpr) {
		this.localIdentity = localIdentity;
		this.peerRouter = peerRouter;
		this.tpr = tpr;
	}

	public void startPeer(PeerConnectionInfo pci) {
		peerConnectionInfo.put(pci.handshakeDetails().remoteKey(), pci);
		startPeer(pci.handshakeDetails().remoteKey());
	}

	public Peer getOrAdd(NoisePublicKey noisePublicKey) {
		return peers.computeIfAbsent(noisePublicKey, this::startPeer);
	}

	private Peer startPeer(NoisePublicKey noisePublicKey) {
		var peer = new Peer(tpr.openChannel(), peerRouter, peerConnectionInfo.computeIfAbsent(noisePublicKey, k -> PeerConnectionInfo.of(localIdentity, k)));
		peers.put(noisePublicKey, peer);
		return peer;
	}

	@Override
	public void close() {
		for (var peer : peers.values()) {
			peer.close();
		}
	}
}
