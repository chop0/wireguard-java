package ax.xz.wireguard.device.message.tunnel;

import ax.xz.wireguard.device.message.PacketElement;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * An uninitialised packet coming from a tun device
 */
public final class UninitialisedIncomingTunnelPacket extends PacketElement {
	private boolean initialised = false;

	public UninitialisedIncomingTunnelPacket(Uninitialised data) {
		super(data);
	}

	/**
	 * Initialises the data in this packet with the given function, and then parses the packet.
	 * May only be called once.
	 *
	 * @param initialiser the consumer that initialises the packet and returns the length of the packet
	 * @return the parsed packet
	 */
	public IncomingTunnelPacket initialise(Receiver initialiser) throws IOException {
		if (initialised) {
			throw new IllegalStateException("Packet already initialised");
		}
		var bb = backing().asByteBuffer();
		initialiser.receive(bb);
		long packetLength = bb.flip().remaining();
		initialised = true;

		return new IncomingTunnelPacket(this, packetLength);
	}

	public interface Receiver {
		void receive(ByteBuffer t) throws IOException;
	}
}
