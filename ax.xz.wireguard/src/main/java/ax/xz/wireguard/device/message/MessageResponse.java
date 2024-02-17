package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.BufferPool;
import ax.xz.wireguard.crypto.CookieGenerator;
import ax.xz.wireguard.crypto.Crypto;
import ax.xz.wireguard.keys.NoisePublicKey;

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
public final class MessageResponse implements Message, AutoCloseable {
	public static final int LENGTH = 4 + 4 + 4 + NoisePublicKey.LENGTH + Crypto.ChaChaPoly1305Overhead + Crypto.ChaChaPoly1305Overhead * 2;
	public static final int TYPE = 2;

	private final BufferPool.BufferGuard bufferGuard;

	MessageResponse(BufferPool.BufferGuard buffer) {
		this.bufferGuard = buffer;
	}

	public static MessageResponse create(BufferPool bufferPool, int localIndex, int remoteIndex, NoisePublicKey localEphemeral, byte[] encryptedEmpty, NoisePublicKey initiatorKey) {
		// RELEASED:  this method is called by HandshakeResponder#HandshakeResponder, which then calls transmitNow on the buffer, which releases it
		var bg = bufferPool.acquire(LENGTH);
		var buffer = bg.buffer().order(ByteOrder.LITTLE_ENDIAN);
		buffer.putInt(TYPE);
		buffer.putInt(localIndex);
		buffer.putInt(remoteIndex);
		buffer.put(localEphemeral.data());
		buffer.put(encryptedEmpty);

		CookieGenerator.appendMacs(initiatorKey.data(), buffer);
		buffer.flip();

		return new MessageResponse(bg);
	}


	public int sender() {
		return bufferGuard.buffer().getInt(4);
	}

	public int receiver() {
		return bufferGuard.buffer().getInt(8);
	}

	public NoisePublicKey ephemeral() {
		byte[] data = new byte[NoisePublicKey.LENGTH];
		bufferGuard.buffer().get(12, data);
		return new NoisePublicKey(data);
	}

	public byte[] encryptedEmpty() {
		byte[] encryptedEmpty = new byte[Crypto.ChaChaPoly1305Overhead];
		bufferGuard.buffer().get(12 + NoisePublicKey.LENGTH, encryptedEmpty);
		return encryptedEmpty;
	}

	public void close() {
		bufferGuard.close();
	}

	public BufferPool.BufferGuard bufferGuard() {
		return bufferGuard;
	}
}
