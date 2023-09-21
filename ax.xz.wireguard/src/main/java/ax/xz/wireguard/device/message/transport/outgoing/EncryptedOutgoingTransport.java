package ax.xz.wireguard.device.message.transport.outgoing;

import ax.xz.wireguard.device.message.OutgoingPeerPacket;
import ax.xz.wireguard.device.message.transport.TransportPacket;

import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;

public final class EncryptedOutgoingTransport extends TransportPacket implements OutgoingPeerPacket {

	EncryptedOutgoingTransport(UnencryptedOutgoingTransport parent, long counter) {
		super(parent, parent.getCiphertextLength());
		COUNTER.set(header, counter);
	}

	public MemorySegment transmissiblePacket() {
		return backing().asSlice(0, length());
	}

	@Override
	public long length() {
		return HEADER_LAYOUT.byteSize() + ciphertextLength;
	}
}
