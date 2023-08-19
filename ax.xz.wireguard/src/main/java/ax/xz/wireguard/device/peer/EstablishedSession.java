package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.handshake.SymmetricKeypair;
import ax.xz.wireguard.message.MessageTransport;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

final class EstablishedSession {
	private final WireguardDevice device;
	private final SymmetricKeypair keypair;

	private final int localIndex;
	private final int remoteIndex;

	private final InetSocketAddress outboundPacketAddress;

	private final Instant expiration = Instant.now().plusSeconds(120);

	public EstablishedSession(WireguardDevice device, SymmetricKeypair keypair, InetSocketAddress outboundPacketAddress, int localIndex, int remoteIndex) {
		this.device = device;
		this.keypair = keypair;
		this.outboundPacketAddress = outboundPacketAddress;

		this.localIndex = localIndex;
		this.remoteIndex = remoteIndex;
	}

	private final ReentrantLock cipherLock = new ReentrantLock();

	public MessageTransport createTransportPacket(ByteBuffer data) {
		cipherLock.lock();

		try {
			var ciphertext = new byte[data.remaining() + 16];

			long counter = cipher(data, ByteBuffer.wrap(ciphertext));
			return MessageTransport.create(remoteIndex, counter, ciphertext);
		} finally {
			cipherLock.unlock();
		}
	}

	public int writeTransportPacket(ByteBuffer data) throws IOException {
		var packet = createTransportPacket(data);
		return device.transmit(outboundPacketAddress, packet.buffer());
	}

	public void decryptTransportPacket(MessageTransport message, ByteBuffer dst) throws BadPaddingException {
		decipher(message.counter(), message.content(), dst);
	}

	/**
	 * @return the counter value used as a nonce for the packet
	 */
	long cipher(ByteBuffer src, ByteBuffer dst) {
		return keypair.cipher(src, dst);
	}

	void decipher(long counter, ByteBuffer src, ByteBuffer dst) throws BadPaddingException {
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
}
