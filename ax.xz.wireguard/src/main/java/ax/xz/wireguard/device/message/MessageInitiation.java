package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.BufferPool;
import ax.xz.wireguard.crypto.CookieGenerator;
import ax.xz.wireguard.crypto.Crypto;
import ax.xz.wireguard.keys.NoisePublicKey;

import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

public final class MessageInitiation implements Message, AutoCloseable {
	public static final int TYPE = 1;
	public static final int LENGTH = 4 + 4 + NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead + NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead + Crypto.TIMESTAMP_LENGTH + Crypto.ChaChaPoly1305Overhead * 2;

	private final BufferPool.BufferGuard bufferGuard;
	
	MessageInitiation(BufferPool.BufferGuard buffer) {
		this.bufferGuard = buffer;
	}

	public static MessageInitiation create(BufferPool bufferPool, int sender, NoisePublicKey ephemeral, byte[] encryptedStatic, byte[] encryptedTimestamp) {
		// RELEASED:  called by HandshakeInitiator#HandshakeInitiator, which then calls transmitNow on the buffer, which releases it
		var bg = bufferPool.acquire(LENGTH);
		var buffer = bg.buffer().order(ByteOrder.LITTLE_ENDIAN);

		buffer.putInt(TYPE);
		buffer.putInt(sender);
		buffer.put(ephemeral.data());
		buffer.put(encryptedStatic);
		buffer.put(encryptedTimestamp);
		buffer.position(buffer.position() + Crypto.ChaChaPoly1305Overhead * 2); // skip macs
		buffer.flip();

		return new MessageInitiation(bg);
	}

	public BufferPool.BufferGuard getSignedBuffer(NoisePublicKey remoteStatic) {
		var buffer = this.bufferGuard.buffer().position(LENGTH - Crypto.ChaChaPoly1305Overhead * 2).limit(LENGTH);
		if (buffer.remaining() < 32)
			throw new IllegalArgumentException("Buffer needs 32 bytes remaining for the macs");

		CookieGenerator.appendMacs(remoteStatic.data(), buffer);

		buffer.flip();
		return bufferGuard;
	}

	public int sender() {
		return bufferGuard.buffer().getInt(4);
	}

	public NoisePublicKey ephemeral() {
		byte[] ephemeral = new byte[NoisePublicKey.LENGTH];
		bufferGuard.buffer().duplicate().position(8).get(ephemeral);
		return new NoisePublicKey(ephemeral);
	}

	public byte[] encryptedStatic() {
		byte[] encryptedStatic = new byte[NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead];
		bufferGuard.buffer().duplicate().position(8 + NoisePublicKey.LENGTH).get(encryptedStatic);
		return encryptedStatic;
	}

	public byte[] encryptedTimestamp() {
		byte[] encryptedTimestamp = new byte[Crypto.TIMESTAMP_LENGTH + Crypto.ChaChaPoly1305Overhead];
		bufferGuard.buffer().duplicate().position(8 + NoisePublicKey.LENGTH + NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead).get(encryptedTimestamp);
		return encryptedTimestamp;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) return true;
		if (obj == null || obj.getClass() != this.getClass()) return false;
		var that = (MessageInitiation) obj;
		return this.sender() == that.sender() &&
			   Objects.equals(this.ephemeral(), that.ephemeral()) &&
			   Arrays.equals(this.encryptedStatic(), that.encryptedStatic()) &&
			   Arrays.equals(this.encryptedTimestamp(), that.encryptedTimestamp());
	}

	@Override
	public int hashCode() {
		return Objects.hash(sender(), ephemeral(), Arrays.hashCode(encryptedStatic()), Arrays.hashCode(encryptedTimestamp()));
	}

	@Override
	public String toString() {
		return "MessageInitiation[" +
			   "sender=" + sender() + ", " +
			   "ephemeral=" + ephemeral() + ", " +
			   "encryptedStatic=" + Arrays.toString(encryptedStatic()) + ", " +
			   "encryptedTimestamp=" + Arrays.toString(encryptedTimestamp()) + ']';
	}

	public void close() {
		bufferGuard.close();
	}
}
