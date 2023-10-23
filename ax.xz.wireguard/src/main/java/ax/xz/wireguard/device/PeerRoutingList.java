package ax.xz.wireguard.device;

import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class PeerRoutingList {
	private final Map<NoisePublicKey, Integer> peerMap = new ConcurrentHashMap<>();

	private final LinkedList<Integer> freeIndices = new LinkedList<>();

	private Peer[] peers;

	public PeerRoutingList() {
		this.peers = new Peer[16];
		for (int i = 0; i < peers.length; i++) {
			freeIndices.add(i);
		}
	}

	public synchronized Peer remove(int index) {
		var oldPeer = peers[index];
		if (oldPeer == null)
			throw new NoSuchElementException("Peer does not exist");

		peerMap.remove(peers[index].getRemoteStatic());
		peers[index] = null;
		freeIndices.addLast(index);

		return oldPeer;
	}

	public int indexOf(NoisePublicKey publicKey) {
		var result = peerMap.get(publicKey);
		if (result == null)
			throw new NoSuchElementException("Peer does not exist");

		return result;
	}

	public synchronized int shuffle(NoisePublicKey key) {
		var peer = remove(indexOf(key));
		return insert(peer);
	}

	public synchronized int insert(Peer peer) {
		if (freeIndices.isEmpty()) {
			resize((int) Math.ceil(peers.length * 1.5));
		}

		var index = freeIndices.removeFirst();
		if (peerMap.put(peer.getRemoteStatic(), index) != null) {
			throw new IllegalStateException("Peer already exists");
		}

		peers[index] = peer;

		return index;
	}

	private synchronized void resize(int newSize) {
		var newPeers = new Peer[newSize];
		System.arraycopy(peers, 0, newPeers, 0, peers.length);
		this.peers = newPeers;
	}

	public Peer get(int index) {
		return peers[index];
	}
}
