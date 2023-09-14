package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.BufferPool;

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
public final class MessageTransport implements Message, AutoCloseable  {
	public static final int TYPE = 4;

	private final BufferPool.BufferGuard bufferGuard;

	MessageTransport(BufferPool.BufferGuard buffer) {
		this.bufferGuard = buffer;
	}

	public int receiver() {
 		return bufferGuard.buffer().getInt(4);
	}

	public long counter() {
		return bufferGuard.buffer().getLong(8);
	}

	public ByteBuffer content() {
		return bufferGuard.buffer().duplicate().position(16);
	}

	public void setCounter(long counter) {
		bufferGuard.buffer().putLong(8, counter);
	}

	/**
	 * Returns a partially-initialised MessageTransport with the message type and receiver index filled in.
	 * The counter and encrypted data must be filled in before sending.
	 * @param bufferPool The buffer pool to use
	 * @param encryptedDataSize The size of the encrypted data
	 * @param receiverIndex The receiver index
	 * @return A partially-initialised MessageTransport.  The underlying buffer must be released after use.
	 */
	public static MessageTransport createWithHeader(BufferPool bufferPool, int encryptedDataSize, int receiverIndex) {
		var bg = bufferPool.acquire(4 + 4 + 8 + encryptedDataSize);
		var buffer = bg.buffer();
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(TYPE);
		buffer.putInt(receiverIndex);
		buffer.putLong(0);
		buffer.position(0);

		return new MessageTransport(bg);
	}

	public BufferPool.BufferGuard bufferGuard() {
		return bufferGuard;
	}

	public void close() {
		bufferGuard.close();
	}
}
