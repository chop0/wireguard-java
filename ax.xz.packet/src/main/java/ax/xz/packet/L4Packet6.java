package ax.xz.packet;

import java.nio.ByteBuffer;

public interface L4Packet6 {
	void write(IPv6 outer, ByteBuffer buf);
	short size();
	byte nextHeader();

	static L4Packet6 parse(byte nextHeader, ByteBuffer buf) {
		if (nextHeader == 0x3A) {
			return ICMPv6.parse(buf);
		} else if (nextHeader == 0x11) {
			return UDP.parse(buf);
		}
		throw new IllegalArgumentException("Unknown L4 protocol: " + nextHeader);
	}

	static short onesComplement(short value) {
		return (short) (~value & 0xFFFF);
	}

	static short onesComplementAdd(short a, short b) {
		int c = (a & 0xFFFF) + (b & 0xFFFF);
		return (short) ((c & 0xFFFF) + (c >> 16));
	}
}
