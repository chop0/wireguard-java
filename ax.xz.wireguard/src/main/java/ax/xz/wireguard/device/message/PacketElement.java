package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.initiation.InitiationPacket;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.response.ResponsePacket;
import ax.xz.wireguard.device.message.transport.TransportPacket;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
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
public class PacketElement implements AutoCloseable {
	private final Consumer<PacketElement> cleanup;

	private final MemorySegment backing;
	private boolean spoilt = false; // becomes true when this element's backing buffer is consumed by a subclass or returned to the pool

//	private final Exception creationStack = new Exception();

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

	/**
	 * An uninitialised packet holds a buffer whose contents are not guaranteed to be valid.
	 * It should be only be used as a stateless precursor to other subclasses of {@link PacketElement}.
	 */
	public static final class Uninitialised extends PacketElement {
		public Uninitialised(MemorySegment backing, Consumer<PacketElement> cleanup) {
			super(backing, cleanup);
		}

		/**
		 * Constructs an uninitialised packet by moving the contents of the given PacketElement.
		 * Uses the same cleanup method as the old packet.
		 * @param old
		 * @return
		 */
		public static Uninitialised ofMoved(PacketElement old) {
			return new Uninitialised(old.moveBacking(), old.cleanup);
		}

		@Override
		protected void finalize() throws Throwable {

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
		public IncomingPeerPacket initialise(Receiver initialiser, NoisePrivateKey localIdentity) throws IOException, BadPaddingException {
			if (initialised) {
				throw new IllegalStateException("Packet already initialised");
			}
			var bb = backing().asByteBuffer();
			var address = initialiser.receive(bb);
			long packetLength = bb.flip().remaining();
			initialised = true;

			var type = backing().get(JAVA_BYTE, 0);
			return switch (type) {
				case InitiationPacket.TYPE -> new IncomingInitiation(this, localIdentity, address);
				case ResponsePacket.TYPE -> new IncomingResponse(this, localIdentity.publicKey(), address);
				case TransportPacket.TYPE -> new UndecryptedIncomingTransport(this, packetLength, address);
				default -> throw new IllegalArgumentException("Invalid message type (%02x)".formatted(type));
			};
		}

		public interface Receiver {
			InetSocketAddress receive(ByteBuffer t) throws IOException;
		}
	}

	@Override
	protected void finalize() throws Throwable {
		super.finalize();
		if (!spoilt) {
			System.err.println("PacketElement not closed:");
//			creationStack.printStackTrace();
		}
	}
}
