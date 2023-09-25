package ax.xz.wireguard.device;

import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.device.peer.PeerConnectionInfo;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.Pool;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PeerManager implements AutoCloseable {
	private final Map<NoisePublicKey, PeerConnectionInfo> peerConnectionInfo = new ConcurrentHashMap<>();
	private final Map<NoisePublicKey, Peer> peers = new ConcurrentHashMap<>();

	private final Pool pool;
	private final NoisePrivateKey localIdentity;

	private final TunPacketRouter tpr;

	public PeerManager(Pool pool, NoisePrivateKey localIdentity, TunPacketRouter tpr) {
		this.pool = pool;
		this.localIdentity = localIdentity;
		this.tpr = tpr;
	}

	public void addPeer(PeerConnectionInfo pci) {
		peerConnectionInfo.put(pci.handshakeDetails().remoteKey(), pci);
	}

	public void setupChannelDownstream(NoisePublicKey noisePublicKey, PeerPacketRouter.PeerPacketChannel channel) {
		if (peers.containsKey(noisePublicKey)) {
			return;
		}

		var peer = new Peer(pool, channel, tpr.openChannel(), peerConnectionInfo.computeIfAbsent(noisePublicKey, k -> PeerConnectionInfo.of(localIdentity, k)));
		peers.put(noisePublicKey, peer);
	}

	@Override
	public void close() {
		for (var peer : peers.values()) {
			peer.close();
		}
	}
}
