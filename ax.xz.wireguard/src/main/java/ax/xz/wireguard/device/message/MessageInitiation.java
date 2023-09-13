package ax.xz.wireguard.device.message;

import ax.xz.wireguard.noise.crypto.CookieGenerator;
import ax.xz.wireguard.noise.crypto.Crypto;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Objects;

public final class MessageInitiation extends PooledMessage implements Message {
	public static final int TYPE = 1;
	public static final int LENGTH = 4 + 4 + NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead + NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead + Crypto.TIMESTAMP_LENGTH + Crypto.ChaChaPoly1305Overhead * 2;

	MessageInitiation(ByteBuffer buffer) {
		super(LENGTH, buffer);
	}

	public static MessageInitiation create(int sender, NoisePublicKey ephemeral, byte[] encryptedStatic, byte[] encryptedTimestamp) {
		var buffer = ByteBuffer.allocateDirect(LENGTH).order(ByteOrder.LITTLE_ENDIAN);

		buffer.putInt(TYPE);
		buffer.putInt(sender);
		buffer.put(ephemeral.data());
		buffer.put(encryptedStatic);
		buffer.put(encryptedTimestamp);
		buffer.position(buffer.position() + Crypto.ChaChaPoly1305Overhead * 2); // skip macs
		buffer.flip();

		return new MessageInitiation(buffer);
	}

	public ByteBuffer getSignedBuffer(NoisePublicKey remoteStatic) {
		var buffer = buffer().position(LENGTH - Crypto.ChaChaPoly1305Overhead * 2).limit(LENGTH);
		if (buffer.remaining() < 32)
			throw new IllegalArgumentException("Buffer needs 32 bytes remaining for the macs");

		CookieGenerator.appendMacs(remoteStatic.data(), buffer);

		buffer.flip();
		return buffer;
	}

	public static MessageInitiation from(ByteBuffer buffer) {
		int type = buffer.getInt(0);
		if (type != TYPE)
			throw new IllegalArgumentException("Wrong type: " + type);

		return new MessageInitiation(buffer);
	}

	public int sender() {
		return buffer().getInt(4);
	}

	public NoisePublicKey ephemeral() {
		byte[] ephemeral = new byte[NoisePublicKey.LENGTH];
		buffer().duplicate().position(8).get(ephemeral);
		return new NoisePublicKey(ephemeral);
	}

	public byte[] encryptedStatic() {
		byte[] encryptedStatic = new byte[NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead];
		buffer().duplicate().position(8 + NoisePublicKey.LENGTH).get(encryptedStatic);
		return encryptedStatic;
	}

	public byte[] encryptedTimestamp() {
		byte[] encryptedTimestamp = new byte[Crypto.TIMESTAMP_LENGTH + Crypto.ChaChaPoly1305Overhead];
		buffer().duplicate().position(8 + NoisePublicKey.LENGTH + NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead).get(encryptedTimestamp);
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

}
