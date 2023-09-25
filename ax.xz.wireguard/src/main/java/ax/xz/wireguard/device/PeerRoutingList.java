package ax.xz.wireguard.device;

import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.net.InetSocketAddress;
import java.util.*;

class PeerRoutingList {
	private final Map<NoisePublicKey, Integer> peerMap = new HashMap<>();

	private final LinkedList<Integer> freeIndices = new LinkedList<>();

	private PeerPacketRouter.PeerPacketChannel[] peers;

	public PeerRoutingList() {
		this.peers = new PeerPacketRouter.PeerPacketChannel[16];
		for (int i = 0; i < peers.length; i++) {
			freeIndices.add(i);
		}
	}

	public PeerPacketRouter.PeerPacketChannel remove(NoisePublicKey peer) {
		return remove(indexOf(peer));
	}

	public PeerPacketRouter.PeerPacketChannel remove(int index) {
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

	public RoutingGuard shuffle(NoisePublicKey key, InetSocketAddress remoteAddress) {
		var peer = remove(indexOf(key));
		return insert(peer, remoteAddress);
	}

	public RoutingGuard insert(PeerPacketRouter.PeerPacketChannel peer, InetSocketAddress remoteAddress) {
		if (freeIndices.isEmpty()) {
			resize((int) Math.ceil(peers.length * 1.5));
		}

		var index = freeIndices.removeFirst();
		if (peerMap.put(peer.getRemoteStatic(), index) != null) {
			throw new IllegalStateException("Peer already exists");
		}

		peers[index] = peer;

		return new RoutingGuard(peer.getRemoteStatic(), remoteAddress, index);
	}

	private void resize(int newSize) {
		var newPeers = new PeerPacketRouter.PeerPacketChannel[newSize];
		System.arraycopy(peers, 0, newPeers, 0, peers.length);
		this.peers = newPeers;
	}

	public boolean contains(NoisePublicKey publicKey) {
		return peerMap.containsKey(publicKey);
	}

	public PeerPacketRouter.PeerPacketChannel peerOf(NoisePublicKey publicKey) {
		return get(indexOf(publicKey));
	}

	public PeerPacketRouter.PeerPacketChannel get(int index) {
		return peers[index];
	}

	public int peerCount() {
		return peers.length - freeIndices.size();
	}

	public Iterator<PeerPacketRouter.PeerPacketChannel> iterator() {
		return new PeerRoutingList.PeerIterator();
	}

	public final class RoutingGuard implements AutoCloseable {
		private final NoisePublicKey publicKey;
		private final InetSocketAddress remoteAddress;
		private final int index;

		private RoutingGuard(NoisePublicKey publicKey, InetSocketAddress remoteAddress, int index) {
			this.publicKey = publicKey;
			this.remoteAddress = remoteAddress;
			this.index = index;
		}

		@Override
		public void close() {
			remove(index);
		}

		/**
		 * Closes this guard and returns a new guard with a different index
		 */
		public RoutingGuard shuffle(InetSocketAddress remoteAddress) {
			return PeerRoutingList.this.shuffle(publicKey, remoteAddress);
		}
		public NoisePublicKey publicKey() {
			return publicKey;
		}

		public InetSocketAddress remoteAddress() {
			return remoteAddress;
		}

		public int index() {
			return index;
		}
	}

	private class PeerIterator implements Iterator<PeerPacketRouter.PeerPacketChannel> {
		private final Iterator<Map.Entry<NoisePublicKey, Integer>> delegate = peerMap.entrySet().iterator();

		@Override
		public boolean hasNext() {
			return delegate.hasNext();
		}

		@Override
		public PeerPacketRouter.PeerPacketChannel next() {
			return peers[delegate.next().getValue()];
		}
	}
}
