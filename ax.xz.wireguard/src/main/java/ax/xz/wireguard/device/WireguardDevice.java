package ax.xz.wireguard.device;

import ax.xz.wireguard.device.message.Message;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;
import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.noise.handshake.Handshakes;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.ScopedLogger;
import org.slf4j.Logger;

import javax.crypto.BadPaddingException;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public final class WireguardDevice implements Closeable {
	public static final ScopedValue<WireguardDevice> CURRENT_DEVICE = ScopedValue.newInstance();

	static {
		ScopedLogger.addScopedMarker("device", CURRENT_DEVICE);
	}

	private static final Logger log = ScopedLogger.getLogger(WireguardDevice.class);

	private final NoisePrivateKey staticIdentity;

	private final ConcurrentHashMap<NoisePublicKey, Peer> peers = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<Integer, Peer> peerSessionIndices = new ConcurrentHashMap<>();

	private final Lock peerLock = new ReentrantLock();
	private final Condition peerCondition = peerLock.newCondition();


	private final DatagramChannel datagramChannel;

	private final AtomicInteger handshakeCounter = new AtomicInteger(0);
	private final AtomicLong bytesSent = new AtomicLong(0);
	private final AtomicLong bytesReceived = new AtomicLong(0);

	private int physicalLayerMTU = 1420;

	public WireguardDevice(NoisePrivateKey staticIdentity) {
		this.staticIdentity = staticIdentity;

		try {
			datagramChannel = DatagramChannel.open();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void deletePeer(NoisePublicKey publicKey) {
		peerLock.lock();

		try {
			peerSessionIndices.remove(peers.remove(publicKey).sessionIndex());
		} finally {
			peerLock.unlock();
		}
	}

	private void deletePeer(Peer peer) {
		deletePeer(peer.getRemoteStatic());
	}


	private final LinkedBlockingQueue<Peer> unstartedPeers = new LinkedBlockingQueue<>();

	private void registerPeer(Peer newPeer) {
		peerLock.lock();

		try {
			var publicKey = newPeer.getRemoteStatic();
			peers.put(publicKey, newPeer);
			peerCondition.signalAll();

			unstartedPeers.add(newPeer);
		} finally {
			peerLock.unlock();
		}
	}

	private Peer addOrGetPeer(NoisePublicKey publicKey, Duration keepaliveInterval) {
		if (peers.containsKey(publicKey))
			return peers.get(publicKey);

		NoisePresharedKey presharedKey = new NoisePresharedKey(new byte[NoisePresharedKey.LENGTH]);
		var newPeer = new Peer(this, null, publicKey, presharedKey, keepaliveInterval);
		registerPeer(newPeer);

		return newPeer;
	}

	public void bind(SocketAddress endpoint) throws IOException {
		datagramChannel.bind(endpoint);
	}

	public void broadcastTransport(ByteBuffer data) throws InterruptedException, IOException {
		peerLock.lock();

		try (var sts = new StructuredTaskScope.ShutdownOnFailure()) {
			for (var peer : peers.values()) {
				sts.fork(() -> peer.writeTransportPacket(data));
			}

			sts.join();
			sts.throwIfFailed();
		} catch (ExecutionException e) {
			if (e.getCause() instanceof IOException ex) {
				throw ex;
			} else if (e.getCause() instanceof InterruptedException ex) {
				throw ex;
			}
		} finally {
			peerLock.unlock();
		}
	}

	public ByteBuffer receiveTransport() throws InterruptedException {
		peerLock.lock();

		try (var sts = new StructuredTaskScope.ShutdownOnSuccess<ByteBuffer>()) {
			while (peers.isEmpty()) {
				peerCondition.await();
			}

			peers.forEachValue(1, peer -> sts.fork(peer::readTransportPacket));

			sts.join();

			return sts.result();
		} catch (ExecutionException e) {
			throw new Error(e);
		} finally {
			peerLock.unlock();
		}
	}

	public void addPeer(NoisePublicKey publicKey, NoisePresharedKey noisePresharedKey, Duration keepaliveInterval, InetSocketAddress endpoint) {
		var newPeer = new Peer(this, endpoint, publicKey, noisePresharedKey, keepaliveInterval);
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
		ScopedValue.runWhere(CURRENT_DEVICE, this, this::run0);
	}

	private void run0() {
		try (var outerExecutor = new PersistentTaskExecutor<>(RuntimeException::new, log)) { // RuntimeException, since we don't expect this to recover
			outerExecutor.submit("Inbound packet listener", () -> {
				while (!Thread.interrupted()) {
					try {
						receive();
					} catch (IOException e) {
						log.error("Error receiving packet", e);
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
			log.debug("Receive loop interrupted", e);
		} catch (Throwable e) {
			log.error("Error in receive loop", e);
			throw e;
		}
	}

	private class PeerExecutor extends StructuredTaskScope<Void> {
		public void submit(Peer peer) {
			Runnable peerRunnable = () -> ScopedValue.runWhere(Peer.CURRENT_PEER, peer, () -> {
				try {
					peer.start();
				} catch (IOException t) {
					log.warn("Error in peer loop;  removing the peer", t);
				} finally {
					deletePeer(peer);
				}
			});

			fork(() -> {
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
			log.warn("Received message with invalid padding");
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
		return addOrGetPeer(remoteStatic, Duration.ofSeconds(30));
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
