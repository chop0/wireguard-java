package ax.xz.wireguard.device;

import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.noise.handshake.Handshakes;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.IPFilter;
import ax.xz.wireguard.util.ReferenceCounted;

import javax.annotation.Nullable;
import javax.annotation.WillClose;
import javax.crypto.BadPaddingException;
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

	// TODO:  this (and the other addPeer) is shit
	public void addPeer(Peer.PeerConnectionInfo connectionInfo) {
		var peer = new Peer(device, device.getStaticIdentity(), device.datagramChannel, device.getBufferPool(), device.inboundTransportQueue, connectionInfo);
		registerPeer(peer);
	}

	private void addPeer(NoisePublicKey publicKey) {
		var peer = new Peer(device, device.getStaticIdentity(), device.datagramChannel, device.getBufferPool(), device.inboundTransportQueue, Peer.PeerConnectionInfo.of(publicKey));
		registerPeer(peer);
	}

	public void handlePacket(IncomingPeerPacket incomingPeerPacket) {
		try {
			int receiverIndex = switch (incomingPeerPacket) {
				case IncomingInitiation initiation -> addPeerFromInitiation(initiation);
				case IncomingResponse response -> response.receiverIndex();
				case UndecryptedIncomingTransport transport -> transport.receiverIndex();
			};

			innerList.get(receiverIndex).routeMessage(incomingPeerPacket);
		} catch (BadPaddingException e) {
			log.log(DEBUG, "Could not decrypt packet", e);
		}
	}

	/**
	 * Attempts to decrypt the public key in the given initiation message and add it to the peer list.
	 * @param initiation the initiation message
	 * @return the index of the peer in the peer list
	 * @throws BadPaddingException if the initiation message could not be decrypted
	 */
	private int addPeerFromInitiation(IncomingInitiation initiation) throws BadPaddingException {
		var originPublicKey = Handshakes.decryptRemoteStatic(device.getStaticIdentity(), initiation.ephemeral(), initiation.encryptedStatic(), initiation.encryptedTimestamp());

		peerListLock.writeLock().lock(); // must be write lock because we might add a new peer

		try {
			if (!innerList.contains(originPublicKey))
				addPeer(originPublicKey);

			return innerList.indexOf(originPublicKey);
		} finally {
			peerListLock.writeLock().unlock();
		}
	}

	public void broadcastPacketToPeers(@WillClose IncomingTunnelPacket data) {
		peerListLock.readLock().lock();

		try (var rc = ReferenceCounted.of(data)) { // ok because it's reference counted
			for (var iterator = innerList.iterator(); iterator.hasNext(); ) {
				var peer = iterator.next();

				peer.sendTransportMessage(rc.retain());
			}
		}  finally {
			peerListLock.readLock().unlock();
		}
	}

	public int allocateNewIndex(NoisePublicKey peer) {
		peerListLock.writeLock().lock();

		try {
			var existingPeer = innerList.peerOf(peer);
			if (existingPeer == null)
				throw new IllegalStateException("Peer does not exist");

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
			innerList.remove(peer.getRemoteStatic());
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

		public Peer remove(int index) {
			var oldPeer = peers[index];
			if (oldPeer == null)
				throw new NoSuchElementException("Peer does not exist");

			peerMap.remove(peers[index].getRemoteStatic());
			peers[index] = null;
			freeIndices.addLast(index);

			return oldPeer;
		}

		public Peer remove(NoisePublicKey peer) {
			return remove(indexOf(peer));
		}

		public int shuffle(NoisePublicKey key) {
			var peer = remove(indexOf(key));
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
					peer.run();
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
