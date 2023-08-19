package ax.xz.wireguard.packet;

import java.nio.ByteBuffer;
import java.util.Arrays;

public sealed interface ICMPv6 extends L4Packet6 {
	static ICMPv6 echoRequest() {
		return new EchoRequest((short) 0x6213, (short) 0, new byte[1024]);
	}

	private static short onesComplement(short value) {
		return (short) (~value & 0xFFFF);
	}

	private static short onesComplementAdd(short a, short b) {
		int c = (a & 0xFFFF) + (b & 0xFFFF);
		return (short) ((c & 0xFFFF) + (c >> 16));
	}

	/*s
		16-bit one's complement of the one's complement sum of the entire ICMPv6 message
	 */
	default short checksum(IPv6 ipv6) {
		var packet = ByteBuffer.allocate(40 + size());
		ipv6.pseudoHeader(packet);
		writeTypeAndCode(packet);
		packet.putShort((short) 0); // checksum is 0 for checksum calculation
		writePayload(packet);
		packet.flip();

		short total = 0;

		while (packet.remaining() > 1) {
			total = onesComplementAdd(total, packet.getShort());
		}

		if (packet.remaining() == 1) {
			total = onesComplementAdd(total, (short) (packet.get() << 8));
		}

		return onesComplement(total);
	}


	@Override
	default void write(IPv6 outer, ByteBuffer buf) {
		writeTypeAndCode(buf);
		buf.putShort(checksum(outer));
		writePayload(buf);
	}

	@Override
	default byte nextHeader() {
		return 58;
	}

	@Override
	default short size() {
		return (short) (4 + variableData().length);
	}

	void writeTypeAndCode(ByteBuffer buf);

	void writePayload(ByteBuffer buf);
	
	byte[] variableData();

	record DestinationUnreachable(Code code, byte[] variableData) implements ICMPv6 {
		public static final byte TYPE = 1;

		public void writeTypeAndCode(ByteBuffer buf) {
			buf.put(TYPE);
			buf.put(code.value);
		}

		public void writePayload(ByteBuffer buf) {
			buf.put(new byte[4]);
			buf.put(variableData);
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			DestinationUnreachable that = (DestinationUnreachable) o;

			if (code != that.code) return false;
			return Arrays.equals(variableData, that.variableData);
		}

		@Override
		public int hashCode() {
			int result = code != null ? code.hashCode() : 0;
			result = 31 * result + Arrays.hashCode(variableData);
			return result;
		}

		enum Code {
			NO_ROUTE_TO_DESTINATION((byte) 0, "No route to destination"),
			COMMUNICATION_WITH_DESTINATION_ADMINISTRATIVELY_PROHIBITED((byte) 1, "Communication with destination administratively prohibited"),
			BEYOND_SCOPE_OF_SOURCE_ADDRESS((byte) 2, "Beyond scope of source address"),
			ADDRESS_UNREACHABLE((byte) 3, "Address unreachable"),
			PORT_UNREACHABLE((byte) 4, "Port unreachable"),
			SOURCE_ADDRESS_FAILED_INGRESS_EGRESS_POLICY((byte) 5, "Source address failed ingress/egress policy"),
			REJECT_ROUTE_TO_DESTINATION((byte) 6, "Reject route to destination"),
			ERROR_IN_SOURCE_ROUTING_HEADER((byte) 7, "Error in Source Routing Header");

			public final byte value;
			public final String description;

			Code(byte value, String description) {
				this.value = value;
				this.description = description;
			}

			@Override
			public String toString() {
				return description;
			}
		}
	}

	record PacketTooBig(int MTU, byte[] variableData) implements ICMPv6 {
		public static final byte TYPE = 2;

		public void writeTypeAndCode(ByteBuffer buf) {
			buf.put(TYPE);
			buf.put((byte) 0);
		}

		public void writePayload(ByteBuffer buf) {
			buf.putInt(MTU);
			buf.put(variableData);
		}

		@Override
		public short size() {
			return (short) (ICMPv6.super.size() + 4);
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			PacketTooBig that = (PacketTooBig) o;

			if (MTU != that.MTU) return false;
			return Arrays.equals(variableData, that.variableData);
		}

		@Override
		public int hashCode() {
			int result = MTU;
			result = 31 * result + Arrays.hashCode(variableData);
			return result;
		}
	}

	record TimeExceeded(Code code, byte[] variableData) implements ICMPv6 {
		public static final byte TYPE = 3;

		public void writeTypeAndCode(ByteBuffer buf) {
			buf.put(TYPE);
			buf.put(code.value);
		}

		public void writePayload(ByteBuffer buf) {
			buf.put(new byte[4]);
			buf.put(variableData);
		}

		enum Code {
			HOP_LIMIT_EXCEEDED_IN_TRANSIT((byte) 0, "Hop limit exceeded in transit"),
			FRAGMENT_REASSEMBLY_TIME_EXCEEDED((byte) 1, "Fragment reassembly time exceeded");

			public final byte value;
			public final String description;

			Code(byte value, String description) {
				this.value = value;
				this.description = description;
			}

			@Override
			public String toString() {
				return description;
			}
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			TimeExceeded that = (TimeExceeded) o;

			if (code != that.code) return false;
			return Arrays.equals(variableData, that.variableData);
		}

		@Override
		public int hashCode() {
			int result = code != null ? code.hashCode() : 0;
			result = 31 * result + Arrays.hashCode(variableData);
			return result;
		}
	}

	record ParameterProblem(Code code, int pointer, byte[] variableData) implements ICMPv6 {
		public static final byte TYPE = 4;

		public void writeTypeAndCode(ByteBuffer buf) {
			buf.put(TYPE);
			buf.put(code.value);
		}

		public void writePayload(ByteBuffer buf) {
			buf.putInt(pointer);
			buf.put(variableData);
		}

		enum Code {
			HEADER_FIELD((byte) 0, "Erroneous header field encountered"),
			UNRECOGNIZED_NEXT_HEADER_TYPE((byte) 1, "Unrecognized Next Header type encountered"),
			UNRECOGNIZED_IPV6_OPTION((byte) 2, "Unrecognized IPv6 option encountered");

			public final byte value;
			public final String description;

			Code(byte value, String description) {
				this.value = value;
				this.description = description;
			}

			@Override
			public String toString() {
				return description;
			}
		}

		@Override
		public short size() {
			return (short) (ICMPv6.super.size() + 4);
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			ParameterProblem that = (ParameterProblem) o;

			if (pointer != that.pointer) return false;
			if (code != that.code) return false;
			return Arrays.equals(variableData, that.variableData);
		}

		@Override
		public int hashCode() {
			int result = code != null ? code.hashCode() : 0;
			result = 31 * result + pointer;
			result = 31 * result + Arrays.hashCode(variableData);
			return result;
		}
	}

	record EchoRequest(short identifier, short sequenceNumber, byte[] variableData) implements ICMPv6 {
		public static final byte TYPE = (byte) 128;

		public void writeTypeAndCode(ByteBuffer buf) {
			buf.put(TYPE);
			buf.put((byte) 0);
		}

		public void writePayload(ByteBuffer buf) {
			buf.putShort(identifier);
			buf.putShort(sequenceNumber);
			buf.put(variableData);
		}

		@Override
		public short size() {
			return (short) (ICMPv6.super.size() + 4);
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			EchoRequest that = (EchoRequest) o;

			if (identifier != that.identifier) return false;
			if (sequenceNumber != that.sequenceNumber) return false;
			return Arrays.equals(variableData, that.variableData);
		}

		@Override
		public int hashCode() {
			int result = identifier;
			result = 31 * result + (int) sequenceNumber;
			result = 31 * result + Arrays.hashCode(variableData);
			return result;
		}
	}

	record EchoReply(short identifier, short sequenceNumber, byte[] variableData) implements ICMPv6 {
		public static final byte TYPE = (byte) 129;

		public void writeTypeAndCode(ByteBuffer buf) {
			buf.put(TYPE);
			buf.put((byte) 0);
		}

		public void writePayload(ByteBuffer buf) {
			buf.putShort(identifier);
			buf.putShort(sequenceNumber);
			buf.put(variableData);
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;

			EchoReply echoReply = (EchoReply) o;

			if (identifier != echoReply.identifier) return false;
			if (sequenceNumber != echoReply.sequenceNumber) return false;
			return Arrays.equals(variableData, echoReply.variableData);
		}

		@Override
		public int hashCode() {
			int result = identifier;
			result = 31 * result + (int) sequenceNumber;
			result = 31 * result + Arrays.hashCode(variableData);
			return result;
		}
	}

	static ICMPv6 parse(ByteBuffer buf) {
		byte type = buf.get();
		byte code = buf.get();
		buf.getShort(); // checksum
		return switch (type) {
			case DestinationUnreachable.TYPE -> {
				byte[] data = new byte[buf.remaining()];
				buf.get(data);
				yield new DestinationUnreachable(DestinationUnreachable.Code.values()[code], data);
			}
			case PacketTooBig.TYPE -> {
				int MTU = buf.getInt();
				byte[] data = new byte[buf.remaining()];
				buf.get(data);
				yield new PacketTooBig(MTU, data);
			}
			case TimeExceeded.TYPE -> {
				byte[] data = new byte[buf.remaining()];
				buf.get(data);
				yield new TimeExceeded(TimeExceeded.Code.values()[code], data);
			}
			case ParameterProblem.TYPE -> {
				int pointer = buf.getInt();
				byte[] data = new byte[buf.remaining()];
				buf.get(data);
				yield new ParameterProblem(ParameterProblem.Code.values()[code], pointer, data);
			}
			case EchoRequest.TYPE -> {
				short identifier = buf.getShort();
				short sequenceNumber = buf.getShort();
				byte[] data = new byte[buf.remaining()];
				buf.get(data);
				yield new EchoRequest(identifier, sequenceNumber, data);
			}
			case EchoReply.TYPE -> {
				short identifier = buf.getShort();
				short sequenceNumber = buf.getShort();
				byte[] data = new byte[buf.remaining()];
				buf.get(data);
				yield new EchoReply(identifier, sequenceNumber, data);
			}
			default -> throw new IllegalArgumentException("Unknown ICMPv6 type: " + type);
		};
	}
}
