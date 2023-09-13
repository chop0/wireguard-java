package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.noise.handshake.SymmetricKeypair;
import ax.xz.wireguard.device.message.MessageTransport;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentLinkedQueue;

final class EstablishedSession {
	private final SymmetricKeypair keypair;

	private final int localIndex;
	private final int remoteIndex;

	private final InetSocketAddress outboundPacketAddress;

	private final Duration keepaliveInterval;
	private Instant lastKeepalive;

	private final Instant expiration = Instant.now().plusSeconds(120);

	public EstablishedSession(SymmetricKeypair keypair, InetSocketAddress outboundPacketAddress, int localIndex, int remoteIndex, Duration keepaliveInterval) {
		this.keypair = keypair;
		this.outboundPacketAddress = outboundPacketAddress;

		this.localIndex = localIndex;
		this.remoteIndex = remoteIndex;
		this.keepaliveInterval = keepaliveInterval;
	}

	private final ConcurrentLinkedQueue<ByteBuffer> bufferPool = new ConcurrentLinkedQueue<>();

	private ByteBuffer getBuffer() {
		var buffer = bufferPool.poll();
		if (buffer == null) {
			buffer = ByteBuffer.allocateDirect(0x1000);
		}
		return buffer;
	}

	private void releaseBuffer(ByteBuffer buffer) {
		buffer.clear();
		bufferPool.add(buffer);
	}

	public MessageTransport createTransportPacket(ByteBuffer data, ByteBuffer ciphertextBuffer) {
		try {
			long counter = cipher(data, ciphertextBuffer);
			ciphertextBuffer.flip();
			return MessageTransport.create(remoteIndex, counter, ciphertextBuffer);
		} catch (ShortBufferException e) {
			throw new Error(e); // should never happen
		}
	}

	public void sendTransportPacket(WireguardDevice device, ByteBuffer data) throws IOException, InterruptedException {
		var ciphertextBuffer = getBuffer();
		try {
			device.transmit(outboundPacketAddress, createTransportPacket(data, ciphertextBuffer).buffer());
		} finally {
			releaseBuffer(ciphertextBuffer);
		}
	}

	public void sendKeepalive(WireguardDevice device) throws IOException, InterruptedException {
		sendTransportPacket(device, ByteBuffer.allocate(0));
		markKeepaliveSent();
	}

	public void decryptTransportPacket(MessageTransport message, ByteBuffer dst) throws BadPaddingException, InterruptedException, ShortBufferException {
		decipher(message.counter(), message.content(), dst);
	}

	/**
	 * @return the counter value used as a nonce for the packet
	 */
	long cipher(ByteBuffer src, ByteBuffer dst) throws ShortBufferException {
		return keypair.cipher(src, dst);
	}

	void decipher(long counter, ByteBuffer src, ByteBuffer dst) throws BadPaddingException, ShortBufferException {
		keypair.decipher(counter, src, dst);
	}

	public Instant expiration() {
		return expiration;
	}

	public int localIndex() {
		return localIndex;
	}

	public InetSocketAddress getOutboundPacketAddress() {
		return outboundPacketAddress;
	}

	@Override
	public String toString() {
		return "EstablishedSession[" +
			   "keypair=" + keypair + ", " +
			   "localIndex=" + localIndex + ", " +
			   "remoteIndex=" + remoteIndex + ']';
	}

	public boolean isExpired() {
		return Instant.now().isAfter(expiration);
	}

	/**
	 * @return true if a keepalive packet should be sent
	 */
	public boolean needsKeepalive() {
		return lastKeepalive == null || lastKeepalive.plus(keepaliveInterval).isBefore(Instant.now());
	}

	/**
	 * To be called after a keepalive packet is sent
	 */
	public void markKeepaliveSent() {
		lastKeepalive = Instant.now();
	}

	public Duration keepaliveInterval() {
		return keepaliveInterval;
	}
}
