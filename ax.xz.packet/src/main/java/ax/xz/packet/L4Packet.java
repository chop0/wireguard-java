package ax.xz.packet;

import java.nio.ByteBuffer;

public interface L4Packet {
	void write(L3Packet outer, ByteBuffer buf);
	short size();
	byte protocol();
	short checksum(L3Packet l3Packet);

	static L4Packet parse(byte nextHeader, ByteBuffer buf) {
		if (nextHeader == 0x3A) {
			return ICMP.parse(buf);
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
