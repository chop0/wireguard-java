package ax.xz.wireguard.packet;

import java.nio.ByteBuffer;

public interface L4Packet6 {
	void write(IPv6 outer, ByteBuffer buf);
	short size();
	byte nextHeader();

	static L4Packet6 parse(byte nextHeader, ByteBuffer buf) {
		if (nextHeader == 0x3A) {
			return ICMPv6.parse(buf);
		}
		throw new IllegalArgumentException("Unknown L4 protocol: " + nextHeader);
	}
}
