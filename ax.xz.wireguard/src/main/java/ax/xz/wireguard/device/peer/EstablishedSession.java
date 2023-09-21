package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;
import ax.xz.wireguard.noise.handshake.SymmetricKeypair;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static java.lang.System.Logger.Level.ERROR;

final class EstablishedSession implements AutoCloseable {
	private static final System.Logger log = System.getLogger(EstablishedSession.class.getName());

	private final SymmetricKeypair keypair;
	private final InetSocketAddress outboundPacketAddress;
	private final int remoteIndex;

	private final Duration keepaliveInterval;

	// TODO: make this configurable
	private final Instant expiration = Instant.now().plusSeconds(120);

	/**
	 * A queue for peer-bound, encrypted, transport packets.
	 * These packets are here because they don't make sense to send if the session dies, since that presumably
	 * destroys the remote's keypair.
	 */
	private final BlockingQueue<EncryptedOutgoingTransport> outboundSessionQueue = new LinkedBlockingQueue<>();


	/**
	 * The worker thread that sends the packets in {@link #outboundSessionQueue}.
	 */
	private final Thread outboundSessionWorker;

	/**
	 * The channel through which we send transport packets to the peer
	 */
	private final DatagramChannel channel;

	public EstablishedSession(SymmetricKeypair keypair, InetSocketAddress outboundPacketAddress, int remoteIndex, Duration keepaliveInterval) throws IOException {
		this.keypair = keypair;
		this.outboundPacketAddress = outboundPacketAddress;

		this.remoteIndex = remoteIndex;
		this.keepaliveInterval = keepaliveInterval;
		this.channel = DatagramChannel.open();

		this.outboundSessionWorker = Thread.startVirtualThread(this::outboundSessionWorker);
	}

	private void outboundSessionWorker() {
		try {
			while (!Thread.interrupted()) {
				var packet = outboundSessionQueue.take();
				channel.send(packet.transmissiblePacket().asByteBuffer(), outboundPacketAddress);
			}
		} catch (IOException e) {
			log.log(ERROR, "Error sending packet", e);
		} catch (InterruptedException ignored) {
			// shutdown
		}
	}

	@Override
	public void close() throws InterruptedException {
		outboundSessionWorker.interrupt();
		keypair.clean();

		if (!outboundSessionWorker.join(Duration.ofSeconds(5))) {
			log.log(ERROR, "Failed to join outbound session worker thread");
		}
	}

	/**
	 * Enqueues an encrypted transport packet to be sent to the connected peer over a UDP socket.
	 * @param packet the packet to be sent
	 * @return true if the packet was successfully enqueued
	 */
	public boolean sendOutgoingTransport(EncryptedOutgoingTransport packet) {
		return outboundSessionQueue.offer(packet);
	}

	public void decryptTransportPacket(long counter, MemorySegment ciphertext, MemorySegment plaintext) throws BadPaddingException {
		keypair.decipher(counter, ciphertext, plaintext);
	}

	/**
	 * @return the counter value used as a nonce for the packet
	 */
	public long cipher(MemorySegment plaintext, MemorySegment ciphertext) {
		return keypair.cipher(plaintext, ciphertext);
	}

	public Instant expiration() {
		return expiration;
	}

	public InetSocketAddress getOutboundPacketAddress() {
		return outboundPacketAddress;
	}

	@Override
	public String toString() {
		return "EstablishedSession[" +
			   "keypair=" + keypair + ", " +
			   "remoteIndex=" + remoteIndex + ']';
	}

	public boolean isExpired() {
		return Instant.now().isAfter(expiration);
	}

	Duration keepaliveInterval() {
		return keepaliveInterval;
	}

	public int getRemoteIndex() {
		return remoteIndex;
	}
}
