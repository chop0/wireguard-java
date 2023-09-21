package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.initiation.InitiationPacket;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.response.ResponsePacket;
import ax.xz.wireguard.device.message.transport.TransportPacket;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.function.Consumer;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

/**
 * {@link PacketElement} is the mechanism used to manage all buffers used throughout the lifecycle of a packet.
 */
public sealed class PacketElement implements AutoCloseable permits PacketElement.IncomingTunnelPacket, PacketElement.Uninitialised, PacketElement.UninitialisedIncomingTunnelPacket, PacketElement.UnparsedIncomingPeerPacket, InitiationPacket, ResponsePacket, TransportPacket {
	private final Consumer<PacketElement> cleanup;

	private final MemorySegment backing;
	private boolean spoilt = false; // becomes true when this element's backing buffer is consumed by a subclass or returned to the pool

	private PacketElement(MemorySegment backing, Consumer<PacketElement> cleanup) {
		this.backing = backing;
		this.cleanup = cleanup;
	}

	protected PacketElement(PacketElement data) {
		this(data.moveBacking(), data.cleanup);
	}

	protected MemorySegment moveBacking() {
		if (spoilt) {
			throw new IllegalStateException("Backing buffer already consumed");
		}

		spoilt = true;
		return backing;
	}

	public void close() {
		if (spoilt)
			throw new IllegalStateException("Backing buffer already consumed");

		cleanup.accept(this);
		spoilt = true;
	}

	protected MemorySegment backing() {
		if (spoilt)
			throw new IllegalStateException("Backing buffer already consumed");

		return backing;
	}

	public static final class Uninitialised extends PacketElement {
		public Uninitialised(MemorySegment backing, Consumer<PacketElement> cleanup) {
			super(backing, cleanup);
		}

		public static Uninitialised ofMoved(PacketElement old) {
			return new Uninitialised(old.moveBacking(), old.cleanup);
		}
	}

	/**
	 * A message coming in from another peer
	 */
	public static final class UnparsedIncomingPeerPacket extends PacketElement {
		private boolean initialised = false;

		public UnparsedIncomingPeerPacket(Uninitialised backing) {
			super(backing);
		}

		/**
		 * Initialises the data in this packet with the given function, and then parses the packet.
		 * May only be called once.
		 * @param initialiser the consumer that initialises the packet and returns the length of the packet
		 * @return the parsed packet
		 */
		public IncomingPeerPacket initialise(Receiver initialiser, NoisePublicKey localPublicKey) throws IOException, BadPaddingException {
			if (initialised) {
				throw new IllegalStateException("Packet already initialised");
			}
			var bb = backing().asByteBuffer();
			var address = initialiser.receive(bb);
			long packetLength = bb.flip().remaining();
			initialised = true;

			var type = backing().get(JAVA_BYTE, 0);
			return switch (type) {
				case InitiationPacket.TYPE -> new IncomingInitiation(this, localPublicKey, address);
				case ResponsePacket.TYPE -> new IncomingResponse(this, localPublicKey, address);
				case TransportPacket.TYPE -> new UndecryptedIncomingTransport(this, packetLength, address);
				default -> throw new IllegalArgumentException("Invalid message type (%02x)".formatted(type));
			};
		}

		public interface Receiver {
			InetSocketAddress receive(ByteBuffer t) throws IOException;
		}
	}

	/**
	 * An uninitialised packet coming from a tun device
	 */
	public static final class UninitialisedIncomingTunnelPacket extends PacketElement {
		private boolean initialised = false;

		public UninitialisedIncomingTunnelPacket(Uninitialised data) {
			super(data);
		}

		/**
		 * Initialises the data in this packet with the given function, and then parses the packet.
		 * May only be called once.
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

	/**
	 * An IncomingTunnelPacket is a packet coming from a tun device.  Unlike most {@link PacketElement}s, which
	 * are returned to the pool after the first invocation of {@link PacketElement#close}, {@link IncomingTunnelPacket} reference-counted
	 * so it may be sent to multiple peers before being returned to the pool.
	 */
	public static final class IncomingTunnelPacket extends PacketElement {
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

}
