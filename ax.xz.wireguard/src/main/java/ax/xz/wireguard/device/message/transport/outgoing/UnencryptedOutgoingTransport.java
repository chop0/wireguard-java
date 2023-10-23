package ax.xz.wireguard.device.message.transport.outgoing;

import ax.xz.wireguard.device.message.transport.TransportPacket;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.function.Function;

public final class UnencryptedOutgoingTransport extends TransportPacket {

	public UnencryptedOutgoingTransport(Uninitialised backing, long ciphertextLength, int receiverIndex) {
		super(backing, ciphertextLength);
		header.set(ValueLayout.JAVA_BYTE, 0, TYPE);
		RECEIVER_INDEX.set(header, receiverIndex);
	}

	/**
	 * Fills the ciphertext with the given lambda
	 * @param ciphertextFiller the consumer that fills the ciphertext
	 */
	public EncryptedOutgoingTransport fillCiphertext(Function<MemorySegment, Long> ciphertextFiller) {
		long counter = ciphertextFiller.apply(super.ciphertextBuffer);
		return new EncryptedOutgoingTransport(this, counter);
	}

}
