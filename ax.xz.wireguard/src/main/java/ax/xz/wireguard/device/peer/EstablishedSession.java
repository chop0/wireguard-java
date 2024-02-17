package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.BufferPool;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.handshake.SymmetricKeypair;
import ax.xz.wireguard.device.message.MessageTransport;

import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;

final class EstablishedSession {
	private final SymmetricKeypair keypair;

	private final int remoteIndex;

	private final InetSocketAddress outboundPacketAddress;

	private final BufferPool bufferPool;

	private final Duration keepaliveInterval;
	private Instant lastKeepalive;

	private final Instant expiration = Instant.now().plusSeconds(120);

	public EstablishedSession(BufferPool bufferPool, SymmetricKeypair keypair, InetSocketAddress outboundPacketAddress, int remoteIndex, Duration keepaliveInterval) {
		this.bufferPool = bufferPool;
		this.keypair = keypair;
		this.outboundPacketAddress = outboundPacketAddress;

		this.remoteIndex = remoteIndex;
		this.keepaliveInterval = keepaliveInterval;
	}

	public MessageTransport createTransportPacket(ByteBuffer unencryptedData) {
		try {
			var transport = MessageTransport.createWithHeader(bufferPool, unencryptedData.remaining() + 16, remoteIndex);
			long counter = cipher(unencryptedData, transport.content());
			transport.setCounter(counter);

			return transport;
		} catch (ShortBufferException e) {
			throw new Error(e); // should never happen
		}
	}

	public void sendKeepalive(WireguardDevice device) throws IOException {
		var transport = createTransportPacket(BufferPool.empty());

		try {
			device.transmitNow(outboundPacketAddress, transport.bufferGuard());
			markKeepaliveSent();
		} catch (IOException e) {
			transport.close();
			throw e;
		}
	}

	public void decryptTransportPacket(MessageTransport message, ByteBuffer dst) throws BadPaddingException, ShortBufferException {
		decipher(message.counter(), message.content(), dst);
	}

	/**
	 * @return the counter value used as a nonce for the packet
	 */
	long cipher(ByteBuffer src, ByteBuffer dst) throws ShortBufferException {
		return keypair.cipher(src, dst);
	}

	void decipher(long counter, ByteBuffer src, ByteBuffer dst) throws BadPaddingException {
		keypair.decipher(counter, src, dst);
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
