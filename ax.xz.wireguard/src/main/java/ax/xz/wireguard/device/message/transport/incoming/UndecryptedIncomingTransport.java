package ax.xz.wireguard.device.message.transport.incoming;

import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.transport.TransportPacket;

import javax.crypto.BadPaddingException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305Overhead;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * Use this packet when you're receiving transport data from another peer.
 * Has space for the plaintext to be decrypted.
 */
public final class UndecryptedIncomingTransport extends TransportPacket implements IncomingPeerPacket {
	private final InetSocketAddress sender;

	public UndecryptedIncomingTransport(UnparsedIncomingPeerPacket backing, long packetLength, InetSocketAddress sender) {
		super(backing, packetLength - HEADER_LAYOUT.byteSize());
		this.sender = sender;

		if (header.get(JAVA_BYTE, 0) != TYPE) {
			throw new IllegalArgumentException("Invalid message type (expected " + TYPE + " but got " + header.get(JAVA_BYTE, 0) + ")");
		}
	}

	public DecryptedIncomingTransport decrypt(DecryptionFunction decryptionFunction) throws BadPaddingException {
		var plaintextBuffer = backing().asSlice(HEADER_LAYOUT.byteSize() + ciphertextLength, ciphertextLength - ChaChaPoly1305Overhead);
		decryptionFunction.decrypt(super.getCounter(), ciphertextBuffer, plaintextBuffer);
		return new DecryptedIncomingTransport(this, plaintextBuffer);
	}

	@Override
	public InetSocketAddress originAddress() {
		return sender;
	}

	@Override
	public long length() {
		return HEADER_LAYOUT.byteSize() + ciphertextLength;
	}

	public int receiverIndex() {
		return (int) RECEIVER_INDEX.get(header);
	}

	public interface DecryptionFunction {
		void decrypt(long counter, MemorySegment ciphertext, MemorySegment plaintext) throws BadPaddingException;
	}
}
