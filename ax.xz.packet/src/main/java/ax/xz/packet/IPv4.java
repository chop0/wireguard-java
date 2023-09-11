package ax.xz.packet;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ThreadLocalRandom;

public record IPv4(short dscp, byte ecn, short identification, byte flags, short fragmentOffset, byte ttl, Inet4Address source, Inet4Address destination, L4Packet payload) implements L3Packet {
	public IPv4 {
		if (ecn < 0 || ecn > 3)
			throw new IllegalArgumentException("Invalid IPv4 ECN");
	}

	@Override
	public void write(ByteBuffer buf) {
		buf.put((byte) ((0x4 << 4) | 5));
		buf.put((byte) ((dscp << 2) | ecn));
		buf.putShort((short) size());

		buf.putShort(identification);
		buf.putShort((short) ((flags << 14) | fragmentOffset));

		buf.put(ttl);
		buf.put(payload.protocol());
		buf.putShort(checksum());

		buf.put(source.getAddress());
		buf.put(destination.getAddress());

		payload.write(this, buf);
	}

	private short checksum() {
		var buf = ByteBuffer.allocateDirect(size() - payload.size());
		buf.put((byte) ((0x4 << 4) | 5));
		buf.put((byte) ((dscp << 2) | ecn));
		buf.putShort((short) size());

		buf.putShort(identification);
		buf.putShort((short) ((flags << 14) | fragmentOffset));

		buf.put(ttl);
		buf.put(payload.protocol());
		buf.putShort((short) 0); // checksum is 0 for checksum calculation

		buf.put(source.getAddress());
		buf.put(destination.getAddress());

		buf.flip();

		short total = 0;

		while (buf.remaining() > 1) {
			total = L4Packet.onesComplementAdd(total, buf.getShort());
		}

		if (buf.remaining() == 1) {
			total = L4Packet.onesComplementAdd(total, (short) (buf.get() << 8));
		}

		return L4Packet.onesComplement(total);
	}

	public void pseudoHeader(ByteBuffer buf) {
		buf.put(source.getAddress());
		buf.put(destination.getAddress());

		buf.put((byte) 0);
		buf.put(payload.protocol());
		buf.putShort((short) payload.size());
	}

	@Override
	public int size() {
		return 20 + payload.size();
	}

	public static IPv4 of(Inet4Address source, Inet4Address destination, L4Packet payload) {
		return new IPv4((byte) 0, (byte)0, (byte) ThreadLocalRandom.current().nextInt(), (byte)0, (byte) 0, (byte) 64, source, destination, payload);
	}

	public static IPv4 parse(ByteBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);

		byte versionIHL = buf.get();
		byte ihl = (byte) (versionIHL & 0xF);
		byte version = (byte) ((versionIHL >> 4) & 0xF);
		if (version != 4)
			throw new IllegalArgumentException("Invalid IPv4 version");

		byte dscpEcn = buf.get();
		byte dscp = (byte) (dscpEcn >> 2);
		byte ecn = (byte) (dscpEcn & 0x3);

		short totalLength = buf.getShort();
		short identification = buf.getShort();
		short flagsFragmentOffset = buf.getShort();
		byte flags = (byte) ((flagsFragmentOffset >> 13) & 0x7);
		short fragmentOffset = (short) (flagsFragmentOffset & 0x1FFF);
		byte ttl = buf.get();
		byte protocol = buf.get();
		short checksum = buf.getShort();
		byte[] source = new byte[4];
		buf.get(source);
		byte[] destination = new byte[4];
		buf.get(destination);
		L4Packet payload = L4Packet.parse(protocol, buf);
		try {
			return new IPv4(dscp, ecn, identification, flags, fragmentOffset, ttl, (Inet4Address) Inet4Address.getByAddress(source), (Inet4Address) Inet4Address.getByAddress(destination), payload);
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}
}
