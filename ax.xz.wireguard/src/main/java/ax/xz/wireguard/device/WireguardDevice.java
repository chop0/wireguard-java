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
import ax.xz.wireguard.util.PersistentTaskExecutor;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteOrder;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.time.Duration;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

public final class WireguardDevice implements Closeable {
	private static final Logger log = System.getLogger(WireguardDevice.class.getName());

	private final NoisePrivateKey staticIdentity;

	private final PeerList peerList = new PeerList(this);

	private final DatagramChannel datagramChannel;
	private final Selector selector;

	// a list of encrypted, incoming packets waiting to be sent up the protocol stack
	final LinkedBlockingQueue<BufferPool.BufferGuard> inboundTransportQueue = new LinkedBlockingQueue<>(ForkJoinPool.getCommonPoolParallelism() * 1024);

	// a list of encrypted, outgoing packets waiting to be sent out
	final LinkedBlockingQueue<EnqueuedPacket> outboundTransportQueue = new LinkedBlockingQueue<>(ForkJoinPool.getCommonPoolParallelism() * 1024);

	private final AtomicInteger handshakeCounter = new AtomicInteger(0);
	private final AtomicLong bytesSent = new AtomicLong(0);
	private final AtomicLong bytesReceived = new AtomicLong(0);
	private final AtomicLong dataSent = new AtomicLong(0);

	private final BufferPool bufferPool = new BufferPool(0x1000, 0x200, 0x400);
	private final int receiveBufferLength = 0x1000;

	public WireguardDevice(NoisePrivateKey staticIdentity) {
		this.staticIdentity = staticIdentity;

		try {
			datagramChannel = DatagramChannel.open();
			datagramChannel.configureBlocking(false);

			selector = Selector.open();
			datagramChannel.register(selector, SelectionKey.OP_READ);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void run() {
		try (var outerExecutor = new PersistentTaskExecutor<>(RuntimeException::new, log, Thread.ofPlatform().factory())) { // RuntimeException, since we don't expect this to recover
			outerExecutor.submit("Peer packet listener", () -> {
				while (!Thread.interrupted()) {
					try {
						receiveMessageInwards();
					} catch (Message.InvalidMessageException e) {
						log.log(DEBUG, "Received invalid message", e);
					} catch (IOException e) {
						log.log(ERROR, "Error receiving packet", e);
						if (!datagramChannel.isOpen())
							break;
					}
				}
			});

			outerExecutor.submit("Peer packet transmitter", () -> {
				while (!Thread.interrupted()) {
					var datagram = outboundTransportQueue.take();

					try {
						datagramChannel.send(datagram.data.buffer(), datagram.address);
					} catch (IOException e) {
						log.log(ERROR, "Error sending packet", e);
					} finally {
						datagram.data.close();
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

	public void broadcastTransportOutwards(BufferPool.BufferGuard data) throws IOException {
		peerList.broadcastMessageOutwards(data);
	}

	private void receiveMessageInwards() throws IOException {
		try {
			// RELEASED:  this buffer is wrapped in a Message and passed to handleMessage, which releases it
			var bg = bufferPool.acquire(receiveBufferLength);
			bg.buffer().order(ByteOrder.LITTLE_ENDIAN);

			if (selector.select() > 0) {
				var addr = datagramChannel.receive(bg.buffer());
				bg.buffer().flip();
				int recv = bg.buffer().remaining();
				bytesReceived.addAndGet(recv);

				handleMessage((InetSocketAddress) addr, Message.parse(bg));
				selector.selectedKeys().clear();
			}
		} catch (BadPaddingException e) {
			log.log(WARNING, "Received message with invalid padding");
		}
	}

	/**
	 * Returns a buffer containing a decrypted transport packet.
	 *
	 * @return the buffer containing the decrypted transport packet.  The buffer must be released to this device's buffer pool after use.
	 * @throws InterruptedException if the thread is interrupted while waiting for a peer to be available
	 */
	public BufferPool.BufferGuard receiveIncomingTransport() throws InterruptedException {
		return inboundTransportQueue.take();
	}

	public void addPeer(NoisePublicKey publicKey, NoisePresharedKey noisePresharedKey, Duration keepaliveInterval, @Nullable InetSocketAddress endpoint) {
		peerList.addPeer(publicKey, noisePresharedKey, keepaliveInterval, endpoint);
	}

	public int allocateNewSessionIndex(Peer peer) {
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
	 * @param address
	 * @param message
	 * @throws BadPaddingException
	 */
	private void handleMessage(InetSocketAddress address, Message message) throws BadPaddingException {
		switch (message) {
			case MessageInitiation initiation -> {
				var remoteStatic = Handshakes.decryptRemoteStatic(staticIdentity, initiation.ephemeral(), initiation.encryptedStatic(), initiation.encryptedTimestamp());
				peerList.routeMessageInwards(address, remoteStatic, initiation);
			}
			case MessageTransport transport -> peerList.routeMessageInwards(address, transport.receiver(), transport);
			case MessageResponse response -> peerList.routeMessageInwards(address, response.receiver(), response);
			default -> throw new IllegalArgumentException("Unknown message type");
		}
	}

	/**
	 * Sends a packet immediately, bypassing the queue
	 *
	 * @param address the address to send to
	 * @param data    the data to send.  must be a buffer allocated from the buffer pool
	 * @throws IOException if something goes wrong with the socket
	 */
	public void transmitNow(SocketAddress address, BufferPool.BufferGuard data) throws IOException {
		int sent = data.buffer().remaining();
		datagramChannel.send(data.buffer(), address);
		data.close();
		bytesSent.addAndGet(sent);
	}

	/**
	 * Enqueues a packet to be sent to the given address.
	 *
	 * @param address the address to send to
	 * @param data    the data to send.  must be a buffer allocated from the buffer pool
	 */
	public void queueTransmit(SocketAddress address, BufferPool.BufferGuard data) {
		outboundTransportQueue.offer(new EnqueuedPacket(address, data));
	}

	public DeviceStats getStats() {
		return new DeviceStats(peerList.peerCount(), handshakeCounter.get(), bytesSent.get(), bytesReceived.get());
	}

	public BufferPool getBufferPool() {
		return bufferPool;
	}

	@Override
	public String toString() {
		return "Device[%s]".formatted(staticIdentity.publicKey().toString().substring(0, 8));
	}

	record EnqueuedPacket(SocketAddress address, BufferPool.BufferGuard data) {
	}
}
