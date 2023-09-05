package ax.xz.packet;

import java.nio.ByteBuffer;

public record UDP(int sourcePort, int destinationPort, byte[] data) implements L4Packet {
	public static UDP datagram(int srcPort, int dstPort, byte[] data) {
		return new UDP(srcPort, dstPort, data);
	}
	public static UDP parse(ByteBuffer buf) {
		int sourcePort = buf.getShort() & 0xFFFF;
		int destinationPort = buf.getShort() & 0xFFFF;
		int length = buf.getShort() & 0xFFFF;
		short checksum = buf.getShort();
		byte[] data = new byte[length - 8];
		buf.get(data);
		return new UDP(sourcePort, destinationPort, data);
	}

	public short checksum(L3Packet ipv6) {
		var packet = ByteBuffer.allocateDirect(ipv6.size());
		ipv6.pseudoHeader(packet);

		packet.putShort((short) sourcePort);
		packet.putShort((short) destinationPort);
		packet.putShort((short) size());
		packet.putShort((short) 0); // checksum is 0 for checksum calculation
		packet.put(data);
		packet.flip();

		short total = 0;

		while (packet.remaining() > 1) {
			total = L4Packet.onesComplementAdd(total, packet.getShort());
		}

		if (packet.remaining() == 1) {
			total = L4Packet.onesComplementAdd(total, (short) (packet.get() << 8));
		}

		return L4Packet.onesComplement(total);
	}
	@Override
	public void write(L3Packet outer, ByteBuffer buf) {
		buf.putShort((short) sourcePort);
		buf.putShort((short) destinationPort);
		buf.putShort((short) size());
		buf.putShort(checksum(outer));
		buf.put(data);
	}

	@Override
	public short size() {
		return (short) (8 + data.length);
	}

	@Override
	public byte protocol() {
		return 17;
	}
}
