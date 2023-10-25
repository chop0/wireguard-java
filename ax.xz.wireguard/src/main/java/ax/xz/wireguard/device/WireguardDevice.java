package ax.xz.wireguard.device;

import ax.xz.raw.spi.BatchedDatagramSocket;
import ax.xz.raw.spi.BatchedDatagramSocketProvider;
import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.device.message.PacketElement;
import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.PersistentTaskExecutor;

import javax.crypto.BadPaddingException;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

public final class WireguardDevice implements Closeable {

	private static final Logger log = System.getLogger(WireguardDevice.class.getName());

	private final NoisePrivateKey staticIdentity;

	private final PeerList peerList = new PeerList(this);

	final DatagramChannel datagramChannel; // TODO:  rethink how this is exposed and how channels are managed

	private final AtomicInteger handshakeCounter = new AtomicInteger(0);
	private final AtomicLong bytesSent = new AtomicLong(0);
	private final AtomicLong bytesReceived = new AtomicLong(0);

	private final Pool bufferPool = new Pool(0x500);

	final Tun tun;

	public WireguardDevice(NoisePrivateKey staticIdentity, Tun tun) {
		this.staticIdentity = staticIdentity;
		this.tun = tun;

		try {
			datagramChannel = DatagramChannel.open();

		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void run() {
		try (var outerExecutor = new PersistentTaskExecutor<>(RuntimeException::new, log, Thread.ofPlatform().factory())) { // RuntimeException, since we don't expect this to recover
				outerExecutor.submit("Peer packet listener", () -> {
					while (!Thread.interrupted()) {
						try {
							receiveMessageFromPeer();
						} catch (IOException e) {
							log.log(ERROR, "Error receiving packet", e);
						}
					}
				});

			outerExecutor.awaitTermination();
			outerExecutor.throwIfFailed();
		} catch (InterruptedException e) {
			log.log(DEBUG, "Receive loop interrupted", e);
		} catch (Throwable e) {
			log.log(ERROR, "Error in receive loop", e);
			throw e;
		}
	}

	public void bind(SocketAddress endpoint) throws IOException {
		datagramChannel.bind(endpoint);
		log.log(DEBUG, "Bound to {0}", endpoint);
	}

	/**
	 * Sends an IP packet to all of the connected peers.
	 *
	 * @param element an unencrypted packet to encrypt and send to all peers
	 * @throws IOException if something goes wrong with the socket
	 */
	public void broadcastPacketToPeers(IncomingTunnelPacket element) throws IOException {
		peerList.broadcastPacketToPeers(element);
	}

	private void receiveMessageFromPeer() throws IOException {
		var bg = new PacketElement.UnparsedIncomingPeerPacket(bufferPool.acquire());

		try {
			var packet = bg.initialise(bb -> (InetSocketAddress) datagramChannel.receive(bb), staticIdentity.publicKey());
			bytesReceived.addAndGet(packet.length());

			handlePacket(packet);

		} catch (BadPaddingException e) {
			log.log(WARNING, "Received message with invalid padding");
			bg.close();
		}
	}

	public void addPeer(Peer.PeerConnectionInfo connectionInfo) {
		peerList.addPeer(connectionInfo);
	}

	public int allocateNewSessionIndex(NoisePublicKey peer) {
		return peerList.allocateNewIndex(peer);
	}

	public NoisePrivateKey getStaticIdentity() {
		return staticIdentity;
	}

	public void close() throws IOException {
		datagramChannel.close();
	}

	/**
	 * Handles a message received from the given address.
	 * Will eventually release the buffer backing message back to the buffer pool.
	 *
	 * @param message the message to handle
	 * @throws BadPaddingException
	 */
	private void handlePacket(IncomingPeerPacket message) throws BadPaddingException {
		peerList.handlePacket(message);
	}

	public Pool getBufferPool() {
		return bufferPool;
	}

	public DeviceStats getStats() {
		return new DeviceStats(peerList.peerCount(), handshakeCounter.get(), bytesSent.get(), bytesReceived.get());
	}

	@Override
	public String toString() {
		return "Device[%s]".formatted(staticIdentity.publicKey().toString().substring(0, 8));
	}
}
