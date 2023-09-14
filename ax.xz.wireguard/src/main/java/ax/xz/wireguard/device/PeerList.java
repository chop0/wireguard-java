package ax.xz.wireguard.device;

import ax.xz.wireguard.device.message.Message;
import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static java.lang.System.Logger.Level.DEBUG;

class PeerList {
	private static final System.Logger log = System.getLogger(PeerList.class.getName());

	private final WireguardDevice device;

	private final ReentrantReadWriteLock peerListLock = new ReentrantReadWriteLock();
	private final UnprotectedPeerList innerList = new UnprotectedPeerList();

	private final PeerExecutor peerExecutor = new PeerExecutor();

	PeerList(WireguardDevice device) {
		this.device = device;
	}

	public void addPeer(NoisePublicKey publicKey, NoisePresharedKey noisePresharedKey, Duration keepaliveInterval, @Nullable InetSocketAddress endpoint) {
		peerListLock.writeLock().lock();

		try {
			var peer = new Peer(device, device.inboundTransportQueue, new Peer.PeerConnectionInfo(publicKey, noisePresharedKey, endpoint, keepaliveInterval), device.getBufferPool());
			registerPeer(peer);
		} finally {
			peerListLock.writeLock().unlock();
		}
	}

	@GuardedBy("peerListLock.writeLock()")
	private void addPeer(NoisePublicKey publicKey) {
		var peer = new Peer(device, device.inboundTransportQueue, new Peer.PeerConnectionInfo(publicKey, null, null, null), device.getBufferPool());
		registerPeer(peer);
	}

	public void routeMessageInwards(InetSocketAddress origin, NoisePublicKey originPublicKey, Message message) {
		peerListLock.writeLock().lock(); // must be write lock because we might add a new peer

		try {
			if (!innerList.contains(originPublicKey))
				addPeer(originPublicKey);

			var peer = innerList.peerOf(originPublicKey);
			peer.receiveInboundMessage(origin, message);
		} finally {
			peerListLock.writeLock().unlock();
		}
	}

	public void routeMessageInwards(InetSocketAddress origin, int originIndex, Message message) {
		peerListLock.readLock().lock();

		try {
			var peer = innerList.get(originIndex);
			if (peer == null) {
				log.log(DEBUG, "Received message from unknown peer {0}", origin);
				return;
			}

			peer.receiveInboundMessage(origin, message);
		} finally {
			peerListLock.readLock().unlock();
		}
	}

	public void broadcastMessageOutwards(BufferPool.BufferGuard data) {
		peerListLock.readLock().lock();

		try {
			for (var iterator = innerList.iterator(); iterator.hasNext(); ) {
				var peer = iterator.next();

				peer.enqueueTransportPacket(iterator.hasNext() ? data.clone() : data);
			}

			if (innerList.peerCount() == 0) {
				data.close();
			}
		} finally {
			peerListLock.readLock().unlock();
		}
	}

	public int allocateNewIndex(Peer peer) {
		peerListLock.writeLock().lock();

		try {
			var existingPeer = innerList.peerOf(peer.getRemoteStatic());
			if (existingPeer == null)
				throw new IllegalStateException("Peer does not exist");

			if (existingPeer != peer)
				throw new IllegalStateException("A different peer with the same public key already exists");

			return innerList.shuffle(peer);
		} finally {
			peerListLock.writeLock().unlock();
		}
	}

	private void registerPeer(Peer newPeer) {
		peerListLock.writeLock().lock();
		try {
			if (innerList.contains(newPeer.getRemoteStatic()))
				throw new IllegalStateException("Peer already exists");

			innerList.insert(newPeer);
			peerExecutor.submit(newPeer);

			log.log(DEBUG, "Registered peer {0}", newPeer);
		} finally {
			peerListLock.writeLock().unlock();
		}
	}

	public int peerCount() {
		return innerList.peerCount();
	}

	private void deregisterPeer(Peer peer) {
		peerListLock.writeLock().lock();

		try {
			innerList.remove(peer);
			peerExecutor.stopPeer(peer.getRemoteStatic());

			log.log(DEBUG, "Deregistered peer {0}", peer);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException("Could not stop peer", e);
		} finally {
			peerListLock.writeLock().unlock();
		}
	}

	private static class UnprotectedPeerList {
		private final Map<NoisePublicKey, Integer> peerMap = new HashMap<>();

		private final LinkedList<Integer> freeIndices = new LinkedList<>();

		private Peer[] peers;

		public UnprotectedPeerList() {
			this.peers = new Peer[16];
			for (int i = 0; i < peers.length; i++) {
				freeIndices.add(i);
			}
		}

		public Peer get(int index) {
			return peers[index];
		}

		public void remove(int index) {
			peerMap.remove(peers[index].getRemoteStatic());
			peers[index] = null;

			freeIndices.addLast(index);
		}

		public void remove(Peer peer) {
			remove(indexOf(peer.getRemoteStatic()));
		}

		public int shuffle(Peer peer) {
			remove(peer);
			return insert(peer);
		}

		public boolean contains(NoisePublicKey publicKey) {
			return peerMap.containsKey(publicKey);
		}

		public int insert(Peer peer) {
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

		public int indexOf(NoisePublicKey publicKey) {
			var result = peerMap.get(publicKey);
			if (result == null)
				throw new NoSuchElementException("Peer does not exist");

			return result;
		}

		public Peer peerOf(NoisePublicKey publicKey) {
			return get(indexOf(publicKey));
		}

		private void resize(int newSize) {
			var newPeers = new Peer[newSize];
			System.arraycopy(peers, 0, newPeers, 0, peers.length);
			this.peers = newPeers;
		}

		public int peerCount() {
			return peers.length - freeIndices.size();
		}

		public Iterator<Peer> iterator() {
			return new PeerIterator();
		}

		private class PeerIterator implements Iterator<Peer> {
			private final Iterator<Map.Entry<NoisePublicKey, Integer>> delegate = peerMap.entrySet().iterator();

			@Override
			public boolean hasNext() {
				return delegate.hasNext();
			}

			@Override
			public Peer next() {
				return peers[delegate.next().getValue()];
			}
		}
	}

	private class PeerExecutor implements AutoCloseable {
		private final ConcurrentHashMap<NoisePublicKey, Thread> peerTasks = new ConcurrentHashMap<>();

		public void submit(Peer peer) {
			Runnable peerRunnable = () -> {
				try {
					peer.start();
				} finally {
					log.log(DEBUG, "Peer {0} exited", peer);
					deregisterPeer(peer);
				}
			};

			peerTasks.put(peer.getRemoteStatic(), Thread.ofVirtual().name(peer.toString()).start(peerRunnable));
		}

		public void stopPeer(NoisePublicKey publicKey) throws InterruptedException {
			var task = peerTasks.remove(publicKey);
			task.interrupt();
			task.join(Duration.ofSeconds(1));
		}

		@Override
		public void close() {
			try (var sts = Executors.newVirtualThreadPerTaskExecutor()) {
				for (var peer : peerTasks.keySet()) {
					sts.submit(() -> {
						stopPeer(peer);
						return null;
					});
				}

				sts.awaitTermination(1, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}
}
