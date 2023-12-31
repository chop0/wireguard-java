package ax.xz.packet;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public record IPv6(byte trafficClass, int flowLabel, int payloadLength, byte nextHeader, byte hopLimit, Inet6Address source, Inet6Address destination, L4Packet payload) implements L3Packet {
	public IPv6 {
		if (payloadLength < 0 || payloadLength > 0xFFFF)
			throw new IllegalArgumentException("Invalid IPv6 payload length");
	}
	@Override
	public void write(ByteBuffer buf) {
		buf.put((byte) ((0x6 << 4) | (trafficClass >> 4)));
		buf.put((byte) (((trafficClass << 4) & 0xF0) | ((flowLabel >> 16) & 0x0F)));
		buf.putShort((short) (flowLabel & 0xFFFF));
		buf.putShort((short) payloadLength);
		buf.put(nextHeader);
		buf.put(hopLimit);

		buf.put(source.getAddress());
		buf.put(destination.getAddress());

		payload.write(this, buf);
	}

	public void pseudoHeader(ByteBuffer buf) {
		buf.put(source.getAddress());
		buf.put(destination.getAddress());
		buf.putInt(payload.size());
		buf.put((byte) 0);
		buf.put((byte) 0);
		buf.put((byte) 0);

		buf.put(nextHeader);
	}

	@Override
	public int size() {
		return 40 + payload.size();
	}

	public static IPv6 of(Inet6Address source, Inet6Address destination, L4Packet payload) {
		return new IPv6((byte) 0, 0, payload.size(), payload.protocol(), (byte) 64, source, destination, payload);
	}

	public static IPv6 parse(ByteBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);

		byte versionTrafficClass = buf.get();
		byte trafficClass = (byte) ((versionTrafficClass << 4) & 0xF0);
		byte version = (byte) (versionTrafficClass >> 4);
		if (version != 6)
			throw new IllegalArgumentException("Invalid IPv6 version");
		int flowLabel = ((buf.get() & 0xF) << 16) | (buf.getShort() & 0xFFFF);
		int payloadLength = buf.getShort() & 0xFFFF;
		byte nextHeader = buf.get();
		byte hopLimit = buf.get();
		byte[] source = new byte[16];
		buf.get(source);
		byte[] destination = new byte[16];
		buf.get(destination);
		L4Packet payload = L4Packet.parse(nextHeader, buf);
		try {
			return new IPv6(trafficClass, flowLabel, payloadLength, nextHeader, hopLimit, (Inet6Address) InetAddress.getByAddress(source), (Inet6Address) InetAddress.getByAddress(destination), payload);
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}
}
