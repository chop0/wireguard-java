package ax.xz.wireguard.device.message.tunnel;

import ax.xz.wireguard.device.message.PacketElement;

import java.lang.foreign.MemorySegment;

/**
 * An IncomingTunnelPacket is a packet coming from a tun device.  Unlike most {@link PacketElement}s, which
 * are returned to the pool after the first invocation of {@link PacketElement#close}, {@link IncomingTunnelPacket} reference-counted
 * so it may be sent to multiple peers before being returned to the pool.
 */
public final class IncomingTunnelPacket extends PacketElement {
	private final long packetLength;

	public IncomingTunnelPacket(UninitialisedIncomingTunnelPacket data, long packetLength) {
		super(data);
		this.packetLength = packetLength;
	}

	public long length() {
		return packetLength;
	}

	public MemorySegment packet() {
		return backing().asSlice(0, packetLength);
	}
}
