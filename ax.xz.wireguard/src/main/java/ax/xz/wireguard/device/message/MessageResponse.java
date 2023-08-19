package ax.xz.wireguard.device.message;

import ax.xz.wireguard.noise.crypto.CookieGenerator;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.noise.crypto.chacha20poly1305;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * msg = handshake_response {
 *     u8 message_type
 *     u8 reserved_zero[3]
 *     u32 sender_index
 *     u32 receiver_index
 *     u8 unencrypted_ephemeral[32]
 *     u8 encrypted_nothing[AEAD_LEN(0)]
 *     u8 mac1[16]
 *     u8 mac2[16]
 * }
 */
public final class MessageResponse extends PooledMessage implements Message {
	public static final int LENGTH = 4 + 4 + 4 + NoisePublicKey.LENGTH + chacha20poly1305.Overhead + chacha20poly1305.Overhead * 2;
	public static final int TYPE = 2;

	public MessageResponse(ByteBuffer buffer) {
		super(LENGTH, buffer);

		if (buffer().getInt() != TYPE)
			throw new IllegalArgumentException("Wrong type (expected %d, got %d)".formatted(TYPE, buffer().getInt()));
	}

	public static MessageResponse create(int localIndex, int remoteIndex, NoisePublicKey localEphemeral, byte[] encryptedEmpty, NoisePublicKey initiatorKey) {
		var buffer = ByteBuffer.allocate(LENGTH).order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(TYPE);
		buffer.putInt(localIndex);
		buffer.putInt(remoteIndex);
		buffer.put(localEphemeral.data());
		buffer.put(encryptedEmpty);

		CookieGenerator.appendMacs(initiatorKey.data(), buffer);
		buffer.flip();

		return new MessageResponse(buffer);
	}


	public int sender() {
		return buffer().getInt(4);
	}

	public int receiver() {
		return buffer().getInt(8);
	}

	public NoisePublicKey ephemeral() {
		byte[] data = new byte[NoisePublicKey.LENGTH];
		buffer().get(12, data);
		return new NoisePublicKey(data);
	}

	public byte[] encryptedEmpty() {
		byte[] encryptedEmpty = new byte[chacha20poly1305.Overhead];
		buffer().get(12 + NoisePublicKey.LENGTH, encryptedEmpty);
		return encryptedEmpty;
	}
}
