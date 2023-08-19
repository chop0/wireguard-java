package ax.xz.wireguard.device.message;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;

/**
 * msg = packet_data {
 *     u8 message_type
 *     u8 reserved_zero[3]
 *     u32 receiver_index
 *     u64 counter
 *     u8 encrypted_encapsulated_packet[]
 * }
 */
public final class MessageTransport extends PooledMessage implements Message  {
	public static final int TYPE = 4;

	MessageTransport(ByteBuffer buffer) {
		super(buffer.remaining(), buffer);

		if (buffer().getInt() != TYPE)
			throw new IllegalArgumentException("Wrong type");
	}

	public int receiver() {
		return buffer().getInt(4);
	}

	public long counter() {
		return buffer().getLong(8);
	}

	public ByteBuffer content() {
		return buffer().duplicate().position(16);
	}

	public static MessageTransport create(int receiverIndex, long counter, byte[] encryptedData) {
		Objects.requireNonNull(encryptedData);

		var buffer = ByteBuffer.allocate(4 + 4 + 8 + encryptedData.length);
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(TYPE);
		buffer.putInt(receiverIndex);
		buffer.putLong(counter);
		buffer.put(encryptedData);
		buffer.flip();

		return new MessageTransport(buffer);
	}
}
