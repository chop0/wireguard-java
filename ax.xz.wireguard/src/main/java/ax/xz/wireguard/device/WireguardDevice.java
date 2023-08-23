package ax.xz.wireguard.device;

import ax.xz.wireguard.MultipleResultTaskScope;
import ax.xz.wireguard.device.message.Message;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;
import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.noise.handshake.Handshakes;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.crypto.BadPaddingException;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

public final class WireguardDevice implements Closeable {
	public static final ScopedValue<WireguardDevice> CURRENT_DEVICE = ScopedValue.newInstance();

	private static final Logger log = System.getLogger(WireguardDevice.class.getName());

	private final NoisePrivateKey staticIdentity;

	private final ConcurrentHashMap<NoisePublicKey, Peer> peers = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<Integer, Peer> peerSessionIndices = new ConcurrentHashMap<>();

	private final Lock peerListLock = new ReentrantLock();
	private final Condition peerCondition = peerListLock.newCondition();


	private final DatagramChannel datagramChannel;

	private final AtomicInteger handshakeCounter = new AtomicInteger(0);
	private final AtomicLong bytesSent = new AtomicLong(0);
	private final AtomicLong bytesReceived = new AtomicLong(0);
	private final AtomicLong dataSent = new AtomicLong(0);

	private int physicalLayerMTU = 1420;

	public WireguardDevice(NoisePrivateKey staticIdentity) {
		this.staticIdentity = staticIdentity;

		try {
			datagramChannel = DatagramChannel.open();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private final LinkedBlockingQueue<Peer> unstartedPeers = new LinkedBlockingQueue<>();

	private void registerPeer(Peer newPeer) {
		peerListLock.lock();

		try {
			var publicKey = newPeer.getRemoteStatic();
			peers.put(publicKey, newPeer);
			peerCondition.signalAll();

			unstartedPeers.add(newPeer);
		} finally {
			peerListLock.unlock();
		}
	}

	private void deregisterPeer(Peer peer) {
		peerListLock.lock();

		try {
			var publicKey = peer.getRemoteStatic();
			peers.remove(publicKey);
			peerCondition.signalAll();
		} finally {
			peerListLock.unlock();
		}
	}

	public void bind(SocketAddress endpoint) throws IOException {
		datagramChannel.bind(endpoint);
	}

	public void broadcastTransport(ByteBuffer data) throws InterruptedException, IOException {
		peerListLock.lock();

		try (var sts = new MultipleResultTaskScope<Integer>()) {
			for (var peer : peers.values()) {
				sts.fork(() -> {
					try {
						return peer.writeTransportPacket(data);
					} catch (IOException e) {
						log.log(WARNING, "Error sending transport packet", e);
						return 0;
					}
				});
			}

			sts.join();
			sts.results().forEach(dataSent::addAndGet);
		} finally {
			peerListLock.unlock();
		}
	}

	public ByteBuffer receiveTransport() throws InterruptedException {
		try (var sts = new StructuredTaskScope.ShutdownOnSuccess<ByteBuffer>()) {
			peerListLock.lock();

			try {
				while (peers.isEmpty()) {
					peerCondition.await();
				}
				peers.forEachValue(1, peer -> sts.fork(peer::readTransportPacket));
			} finally {
				peerListLock.unlock();
			}

			sts.join();
			return sts.result();
		} catch (ExecutionException e) {
			throw new Error(e);
		}
	}

	public void addPeer(NoisePublicKey publicKey, NoisePresharedKey noisePresharedKey, Duration keepaliveInterval, InetSocketAddress endpoint) {
		var newPeer = new Peer(this, new Peer.PeerConnectionInfo(publicKey, noisePresharedKey, endpoint, keepaliveInterval));
		registerPeer(newPeer);
	}

	public void addOrGetPeer(NoisePublicKey publicKey, Duration keepaliveInterval, InetSocketAddress endpoint) {
		addPeer(publicKey, new NoisePresharedKey(new byte[NoisePresharedKey.LENGTH]), keepaliveInterval, endpoint);
	}

	public void setPeerSessionIndex(NoisePublicKey peerKey, int sessionIndex) {
		var peer = peers.get(peerKey);
		if (peerSessionIndices.put(sessionIndex, peer) == null) {
			handshakeCounter.incrementAndGet();
		}
	}

	public void clearSessionIndex(int sessionIndex) {
		peerSessionIndices.remove(sessionIndex);
	}

	public NoisePrivateKey getStaticIdentity() {
		return staticIdentity;
	}

	public int physicalLayerMTU() {
		return physicalLayerMTU;
	}

	public void setPhysicalLayerMTU(int mtu) {
		this.physicalLayerMTU = mtu;
	}

	public void close() throws IOException {
		datagramChannel.close();
	}

	public void run() {
		ScopedValue.runWhere(CURRENT_DEVICE, this, () -> {
			try (var outerExecutor = new PersistentTaskExecutor<>("Device executor", RuntimeException::new, log)) { // RuntimeException, since we don't expect this to recover
				outerExecutor.submit("Inbound packet listener", () -> {
					while (!Thread.interrupted()) {
						try {
							receive();
						} catch (IOException e) {
							log.log(ERROR, "Error receiving packet", e);
						}
					}
				});

				outerExecutor.submit("Peer starter", () -> {
					try (var peerExecutor = new PeerExecutor()) {
						while (!Thread.interrupted()) {
							var peer = unstartedPeers.take();
							peerExecutor.submit(peer);
						}

						peerExecutor.join();
					}
				});

				outerExecutor.join();
				outerExecutor.throwIfFailed();
			} catch (InterruptedException e) {
				log.log(DEBUG, "Receive loop interrupted", e);
			} catch (Throwable e) {
				log.log(ERROR, "Error in receive loop", e);
				throw e;
			}
		});
	}

	private class PeerExecutor extends StructuredTaskScope<Void> {
		public PeerExecutor() {
			super("Peer executor", Thread.ofVirtual().factory());
		}

		public void submit(Peer peer) {
			Runnable peerRunnable = () -> {
				try {
					peer.start();
				} catch (IOException t) {
					log.log(WARNING, "Error in peer loop", t);
				} finally {
					log.log(DEBUG, "Peer {0} exited", peer);
					deregisterPeer(peer);
				}
			};

			fork(() -> {
				Thread.currentThread().setName(peer.toString());
				peerRunnable.run();
				return null;
			});
		}
	}

	private void receive() throws IOException {
		try {
			var buffer = ByteBuffer.allocateDirect(physicalLayerMTU).order(ByteOrder.LITTLE_ENDIAN);

			var addr = datagramChannel.receive(buffer);
			buffer.flip();
			int recv = buffer.remaining();

			handleMessage((InetSocketAddress) addr, Message.parse(buffer));
			bytesReceived.addAndGet(recv);
		} catch (BadPaddingException e) {
			log.log(WARNING, "Received message with invalid padding");
		}
	}

	private void handleMessage(InetSocketAddress address, Message message) throws BadPaddingException {
		var peer = switch (message) {
			case MessageInitiation initiation -> createPeerFromInitiation(initiation);
			case MessageTransport transport -> peerSessionIndices.get(transport.receiver());
			case MessageResponse response -> peerSessionIndices.get(response.receiver());
			default -> throw new IllegalArgumentException("Unknown message type");
		};

		peer.receiveInboundMessage(address, message);
	}

	private Peer createPeerFromInitiation(MessageInitiation message) throws BadPaddingException {
		var handshake = Handshakes.responderHandshake(staticIdentity, message.ephemeral(), message.encryptedStatic(), message.encryptedTimestamp());

		var remoteStatic = handshake.getRemotePublicKey();
		if (peers.containsKey(remoteStatic))
			return peers.get(remoteStatic);

		NoisePresharedKey presharedKey = new NoisePresharedKey(new byte[NoisePresharedKey.LENGTH]);
		var newPeer = new Peer(this, new Peer.PeerConnectionInfo(remoteStatic, presharedKey, null, Duration.ofSeconds(30)));
		registerPeer(newPeer);

		return newPeer;
	}

	public int transmit(SocketAddress address, ByteBuffer data) throws IOException {
		int sent = data.remaining();
		datagramChannel.send(data, address);
		bytesSent.addAndGet(sent);
		return sent;
	}

	public DeviceStats getStats() {
		return new DeviceStats(peers.size(), handshakeCounter.get(), bytesSent.get(), bytesReceived.get());
	}

	@Override
	public String toString() {
		return "Device[%s]".formatted(staticIdentity.publicKey().toString().substring(0, 8));
	}
}
