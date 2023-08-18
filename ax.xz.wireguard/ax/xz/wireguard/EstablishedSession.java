package ax.xz.wireguard;

import ax.xz.wireguard.message.Message;
import ax.xz.wireguard.message.MessageTransport;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

final class EstablishedSession {
	private final WireguardDevice device;
	private final SymmetricKeypair keypair;

	private final int localIndex;
	private final int remoteIndex;

	private final SocketAddress outboundPacketAddress;

	private final Instant expiration = Instant.now().plusSeconds(120);

	public EstablishedSession(WireguardDevice device, SymmetricKeypair keypair, SocketAddress outboundPacketAddress, int localIndex, int remoteIndex) {
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

	public static class UnexpectedMessageException extends Exception {
		public final Message message;

		public UnexpectedMessageException(Message message) {
			super("Received unexpected message: " + message.getClass().getSimpleName());
			this.message = message;
		}


	}

	public SymmetricKeypair keypair() {
		return keypair;
	}

	public int localIndex() {
		return localIndex;
	}

	public int remoteIndex() {
		return remoteIndex;
	}

	public SocketAddress getOutboundPacketAddress() {
		return outboundPacketAddress;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) return true;
		if (obj == null || obj.getClass() != this.getClass()) return false;
		var that = (EstablishedSession) obj;
		return Objects.equals(this.keypair, that.keypair) &&
			   this.localIndex == that.localIndex &&
			   this.remoteIndex == that.remoteIndex;
	}

	@Override
	public int hashCode() {
		return Objects.hash(keypair, localIndex, remoteIndex);
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
