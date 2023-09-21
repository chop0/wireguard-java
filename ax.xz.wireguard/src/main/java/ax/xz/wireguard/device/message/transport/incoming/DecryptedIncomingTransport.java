package ax.xz.wireguard.device.message.transport.incoming;

import ax.xz.wireguard.device.message.transport.TransportPacket;

import javax.crypto.BadPaddingException;
import java.lang.foreign.MemorySegment;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305Overhead;

public final class DecryptedIncomingTransport extends TransportPacket {
	private final MemorySegment plaintextBuffer;

	DecryptedIncomingTransport(UndecryptedIncomingTransport backing, MemorySegment plaintext) throws BadPaddingException {
		super(backing, backing.getCiphertextLength());
		this.plaintextBuffer = plaintext;
	}

	public MemorySegment plaintextBuffer() {
		return plaintextBuffer.asReadOnly();
	}
}
