package ax.xz.wireguard.device.message.transport;

import ax.xz.wireguard.device.message.PacketElement;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;
import ax.xz.wireguard.device.message.transport.outgoing.UnencryptedOutgoingTransport;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.VarHandle;

import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.MemoryLayout.paddingLayout;
import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.ValueLayout.*;

/**
 * msg = packet_data {
 * u8 message_type
 * u8 reserved_zero[3]
 * u32 receiver_index
 * u64 counter
 * u8 encrypted_encapsulated_packet[]
 * }
 */
public abstract sealed class TransportPacket extends PacketElement permits DecryptedIncomingTransport, UndecryptedIncomingTransport, EncryptedOutgoingTransport, UnencryptedOutgoingTransport {
	public static final byte TYPE = 4;

	protected static final StructLayout HEADER_LAYOUT = structLayout(
		JAVA_BYTE.withName("message_type"),
		paddingLayout(3),
		JAVA_INT.withName("receiver_index"),
		JAVA_LONG.withName("counter")
	);

	protected static final VarHandle RECEIVER_INDEX = HEADER_LAYOUT.varHandle(groupElement("receiver_index"));
	protected static final VarHandle COUNTER = HEADER_LAYOUT.varHandle(groupElement("counter"));

	protected final long ciphertextLength;

	protected final MemorySegment header;
	protected final MemorySegment ciphertextBuffer;

	protected TransportPacket(PacketElement data, long ciphertextLength) {
		super(data);
		this.ciphertextLength = ciphertextLength;

		this.header = backing().asSlice(0, HEADER_LAYOUT);
		this.ciphertextBuffer = backing().asSlice(HEADER_LAYOUT.byteSize(), ciphertextLength);
	}

	protected long getCounter() {
		return (long) COUNTER.get(header);
	}

	public long getCiphertextLength() {
		return ciphertextLength;
	}
}
