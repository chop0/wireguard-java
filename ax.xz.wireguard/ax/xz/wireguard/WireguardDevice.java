package ax.xz.wireguard;

import ax.xz.wireguard.crypto.keys.NoisePresharedKey;
import ax.xz.wireguard.crypto.keys.NoisePrivateKey;
import ax.xz.wireguard.crypto.keys.NoisePublicKey;
import ax.xz.wireguard.message.Message;
import ax.xz.wireguard.message.MessageInitiation;
import ax.xz.wireguard.message.MessageResponse;
import ax.xz.wireguard.message.MessageTransport;
import org.slf4j.Logger;

import javax.crypto.BadPaddingException;
import javax.management.*;
import java.io.Closeable;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class WireguardDevice implements Closeable, WireguardDeviceMBean {
	public static final ScopedValue<WireguardDevice> CURRENT_DEVICE = ScopedValue.newInstance();

	static {
		ScopedLogger.addScopedMarker("device", CURRENT_DEVICE);
	}

	private static final Logger log = ScopedLogger.getLogger(WireguardDevice.class);

	private final NoisePrivateKey staticIdentity;

	private final ConcurrentHashMap<NoisePublicKey, Peer> peers = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<Integer, Peer> peerSessionIndices = new ConcurrentHashMap<>();

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

		try {
			ManagementFactory.getPlatformMBeanServer().registerMBean(this, getObjectName());
		} catch (NotCompliantMBeanException | InstanceAlreadyExistsException e) {
			throw new Error(e);
		} catch (MBeanRegistrationException e) {
			log.warn("Error registering Device MBean", e);
		}
	}

	public static String toUnsignedString(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%d ", b & 0xff));
		}
		return sb.toString();
	}

	public static String toUnsignedString(ByteBuffer data) {
		StringBuilder sb = new StringBuilder();
		data = data.duplicate();
		data.order(ByteOrder.LITTLE_ENDIAN);
		while (data.hasRemaining()) {
			sb.append(String.format("%d ", data.get() & 0xff));
		}
		return sb.toString();
	}

	public void deletePeer(NoisePublicKey publicKey) {
		peerSessionIndices.remove(peers.remove(publicKey).sessionIndex());
	}

	@Override
	public void deletePeer(Peer peer) {
		peerSessionIndices.remove(peer.sessionIndex());
		peers.remove(peer.getRemoteStatic());
	}

	private final LinkedBlockingQueue<Runnable> peerTasks = new LinkedBlockingQueue<>();

	private void registerPeer(Peer newPeer) {
		var publicKey = newPeer.getRemoteStatic();
		peers.put(publicKey, newPeer);

		peerTasks.add(() -> {
			try {
				Thread.currentThread().setName(WireguardDevice.this + "->" + newPeer.getAuthority());
				newPeer.start();
			} catch (IOException e) {
				log.error("Error in peer loop", e);
			} catch (InterruptedException e) {
				log.debug("Peer loop interrupted", e);
			} catch (Throwable t) {
				log.error("Error in peer loop", t);
			} finally {
				peers.remove(publicKey);
				peerSessionIndices.remove(newPeer.sessionIndex());
			}
		});
	}

	private void addPeer(NoisePublicKey publicKey, Duration keepaliveInterval) {
		NoisePresharedKey presharedKey = new NoisePresharedKey(new byte[NoisePresharedKey.LENGTH]);
		var newPeer = new Peer(this, null, publicKey, presharedKey, keepaliveInterval);
		registerPeer(newPeer);
	}

	public void bind(SocketAddress endpoint) throws IOException {
		datagramChannel.bind(endpoint);
	}

	public void broadcastTransport(ByteBuffer data) throws InterruptedException {
		try (var sts = new WorkerThreadScope()) {
			for (var peer : peers.values()) {
				sts.fork(() -> peer.writeTransportPacket(data));
			}

			sts.join();
		}
	}

	@Override
	public void broadcastTransport(byte[] data) throws InterruptedException {
		broadcastTransport(ByteBuffer.wrap(data));
	}

	public ByteBuffer receiveTransport() throws InterruptedException, TimeoutException {
		while (peers.isEmpty())
			Thread.sleep(100);

		try (var sts = new StructuredTaskScope.ShutdownOnSuccess<ByteBuffer>()) {
			peers.forEachValue(1, peer -> sts.fork(peer::readTransportPacket));

			sts.join();

			return sts.result();
		} catch (ExecutionException e) {
			throw new Error(e);
		}
	}

	public void addPeer(NoisePublicKey publicKey, NoisePresharedKey noisePresharedKey, Duration keepaliveInterval, SocketAddress endpoint) {
		var newPeer = new Peer(this, endpoint, publicKey, noisePresharedKey, keepaliveInterval);
		registerPeer(newPeer);
	}

	public void addPeer(NoisePublicKey publicKey, Duration keepaliveInterval, SocketAddress endpoint) {
		addPeer(publicKey, new NoisePresharedKey(new byte[NoisePresharedKey.LENGTH]), keepaliveInterval, endpoint);
	}

	@Override
	public void setPeerSessionIndex(Peer peer, int sessionIndex) {
		if (peerSessionIndices.put(sessionIndex, peer) == null) {
			handshakeCounter.incrementAndGet();
		}
	}

	@Override
	public void clearSessionIndex(int sessionIndex) {
		peerSessionIndices.remove(sessionIndex);
	}

	@Override
	public NoisePrivateKey getStaticIdentity() {
		return staticIdentity;
	}

	public ObjectName getObjectName() {
		try {
			return new ObjectName("ax.xz.wireguard:name=" + this);
		} catch (MalformedObjectNameException e) {
			// This should never happen
			throw new Error(e);
		}
	}

	public int physicalLayerMTU() {
		return physicalLayerMTU;
	}

	public void setPhysicalLayerMTU(int mtu) {
		this.physicalLayerMTU = mtu;
	}

	public void close() {
		try {
			ManagementFactory.getPlatformMBeanServer().unregisterMBean(getObjectName());
		} catch (InstanceNotFoundException | MBeanRegistrationException e) {
			log.warn("Error unregistering device MBean", e);
		}
	}

	public void run() {
		ScopedValue.runWhere(CURRENT_DEVICE, this, this::run0);
	}

	private void run0() {
		try (var peerExecutor = new WorkerThreadScope()) {
			peerTasks.add(() -> {
				while (!Thread.interrupted()) {
					try {
						receive();
					} catch (IOException e) {
						log.error("Error receiving packet", e);
					} catch (InterruptedException e) {
						log.debug("Receive loop interrupted", e);
						break;
					}
				}
			});

			while (!Thread.interrupted()) {
				peerExecutor.fork(peerTasks.take());
			}

			peerExecutor.join();
		} catch (InterruptedException e) {
			log.debug("Receive loop interrupted", e);
		} catch (Throwable e) {
			log.error("Error in receive loop", e);
			throw e;
		}
	}

	private void receive() throws IOException, InterruptedException {
		try {
			var buffer = ByteBuffer.allocateDirect(physicalLayerMTU).order(ByteOrder.LITTLE_ENDIAN);

			var addr = datagramChannel.receive(buffer);
			buffer.flip();
			int recv = buffer.remaining();

			handleMessage(addr, Message.parse(buffer));
			bytesReceived.addAndGet(recv);
		} catch (BadPaddingException e) {
			return;
		}
	}

	private void handleMessage(SocketAddress address, Message message) throws BadPaddingException {
		var peer = switch (message) {
			case MessageInitiation initiation -> handleInitiation(initiation);
			case MessageTransport transport -> peerSessionIndices.get(transport.receiver());
			case MessageResponse response -> peerSessionIndices.get(response.receiver());
			default -> throw new IllegalArgumentException("Unknown message type");
		};

		peer.receiveInboundMessage(address, message);
	}

	private Peer handleInitiation(MessageInitiation message) throws BadPaddingException {
		var handshake = Handshakes.responderHandshake(staticIdentity, message.ephemeral(), message.encryptedStatic(), message.encryptedTimestamp());

		var remoteStatic = handshake.getRemotePublicKey();
		if (!peers.containsKey(remoteStatic)) {
			addPeer(remoteStatic, Duration.ofSeconds(30));
		}

		return peers.get(remoteStatic);
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
	public int getNumberOfHandshakes() {
		return handshakeCounter.get();
	}

	@Override
	public int getNumberOfPeers() {
		return peers.size();
	}

	@Override
	public long getNumberOfBytesSent() {
		return bytesSent.get();
	}

	@Override
	public long getNumberOfBytesReceived() {
		return bytesReceived.get();
	}

	@Override
	public String toString() {
		return "Device[%s]".formatted(staticIdentity.publicKey().toString().substring(0, 8));
	}
}
