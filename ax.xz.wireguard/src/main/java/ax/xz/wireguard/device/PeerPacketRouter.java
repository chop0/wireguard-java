package ax.xz.wireguard.device;

import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.OutgoingPeerPacket;
import ax.xz.wireguard.device.message.PacketElement;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.Pool;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BiConsumer;

import static java.lang.System.Logger.Level.*;

/**
 * <h4>This class receives peer traffic and sends port-specific outbound traffic to peers.</h4>
 *
 * <p>
 * 'port-specific' includes handshake initiation messages and responses, but not transport packets;  WireGuard
 * does not use IP addresses (or ports) to route packets or identify clients after the handshake is complete.
 * </p>
 */
public class PeerPacketRouter implements Runnable {
	private static final System.Logger log = System.getLogger(PeerPacketRouter.class.getName());

	private final NoisePrivateKey localIdentity;
	private final DatagramChannel channel;

	private final BiConsumer<NoisePublicKey, PeerPacketChannel> setupChannelDownstream;
	private final PeerRoutingList routingList;

	private final Pool bufferPool;

	/**
	 * @param bufferPool      The buffer pool to use for packets
	 * @param localIdentity   The local private key
	 * @param newPeerCallback A callback to be called when a possibly-unseen peer starts a handshake with us.  This should set up the downstream consumer of this peer's {@link PeerPacketChannel}
	 * @throws IOException
	 */
	public PeerPacketRouter(Pool bufferPool, NoisePrivateKey localIdentity, BiConsumer<NoisePublicKey, PeerPacketChannel> setupChannelDownstream) throws IOException {
		this.localIdentity = localIdentity;
		this.setupChannelDownstream = setupChannelDownstream;

		this.routingList = new PeerRoutingList();
		this.bufferPool = bufferPool;
		this.channel = DatagramChannel.open();
	}

	public void run() {
		while (!Thread.interrupted()) {
			try {
				var packet = receiveMessageFromPeer();
				var peerChannel = getMessageDestination(packet);
				if (peerChannel == null) {
					log.log(DEBUG, "Received message from unknown peer {0}", peerChannel);
					continue;
				}

				peerChannel.handle(packet);
			} catch (IOException e) {
				log.log(ERROR, "Error receiving packet", e);
				if (!channel.isOpen())
					throw new RuntimeException("Channel closed", e);
			} catch (BadPaddingException e) {
				log.log(WARNING, "Received message with invalid padding");
			}
		}
	}

	private IncomingPeerPacket receiveMessageFromPeer() throws IOException, BadPaddingException {
		var bg = new PacketElement.UnparsedIncomingPeerPacket(bufferPool.acquire());

		try {
			return bg.initialise(bb -> (InetSocketAddress) channel.receive(bb), localIdentity);
		} catch (Throwable e) {
			bg.close();
			throw e;
		}
	}

	private PeerPacketChannel getMessageDestination(IncomingPeerPacket packet) throws BadPaddingException {
		return switch (packet) {
			case IncomingInitiation initiation -> {
				NoisePublicKey publicKey = initiation.remotePublicKey();
				yield maybeCreatePeer(publicKey);
			}
			case IncomingResponse response -> {
				int index = response.receiverIndex();
				yield routingList.get(index);
			}
			case UndecryptedIncomingTransport transport -> {
				int index = transport.receiverIndex();
				yield routingList.get(index);
			}
		};
	}

	public PeerPacketChannel maybeCreatePeer(NoisePublicKey publicKey) {
		if (routingList.contains(publicKey)) // if we've sent a packet to this peer before
			return routingList.peerOf(publicKey);
		else {
			var newPeer = this.new PeerPacketChannel(publicKey);
			setupChannelDownstream.accept(publicKey, newPeer);
			return newPeer;
		}
	}

	void bind(InetSocketAddress address) throws IOException {
		channel.bind(address);
	}

	/**
	 * Each Peer object has a {@link PeerPacketChannel} that manages traffic to and from that peer.
	 *
	 * <p>
	 * Messages are transmitted synchronously to peers via the {@link #send(OutgoingPeerPacket)} method, and
	 * received asynchronously via the {@link #handle(IncomingPeerPacket)} method.
	 * </p>
	 */
	public class PeerPacketChannel implements AutoCloseable {
		private final NoisePublicKey publicKey;

		private final BlockingQueue<IncomingInitiation> initiationQueue;
		private final BlockingQueue<IncomingResponse> responseQueue;
		private final BlockingQueue<UndecryptedIncomingTransport> transportQueue;

		/**
		 * The index that this peer is bound to, or -1 if it is not bound.
		 */
		private PeerRoutingList.RoutingGuard routingGuard;

		PeerPacketChannel(NoisePublicKey publicKey) {
			this.publicKey = publicKey;

			this.initiationQueue = new LinkedBlockingQueue<>();
			this.responseQueue = new LinkedBlockingQueue<>();
			this.transportQueue = new LinkedBlockingQueue<>();

			prepareNewSession(null); // TODO:  kill me
		}

		public IncomingInitiation takeInitiation() throws InterruptedException {
			return initiationQueue.take();
		}

		public IncomingResponse takeResponse() throws InterruptedException {
			return responseQueue.take();
		}

		public UndecryptedIncomingTransport takeTransport() throws InterruptedException {
			return transportQueue.take();
		}

		/**
		 * Prepares to communicate with a new address by setting the
		 * {@link #routingGuard} to a new {@link RoutingGuard} with a newly-allocated index.
		 *
		 * @return
		 */
		public int prepareNewSession(InetSocketAddress remoteAddress) {
			if (routingGuard == null)
				this.routingGuard = routingList.insert(this, remoteAddress);
			else
				this.routingGuard = routingGuard.shuffle(remoteAddress);
			return routingGuard.index();
		}

		/**
		 * Handles an incoming packet from this peer by dispatching it to the appropriate queue
		 */
		private boolean handle(IncomingPeerPacket packet) {
			return switch (packet) {
				case IncomingInitiation initiation -> initiationQueue.offer(initiation);
				case IncomingResponse response -> responseQueue.offer(response);
				case UndecryptedIncomingTransport transport -> transportQueue.offer(transport);
			};
		}

		/**
		 * Gets the remote peer's public key
		 */
		public NoisePublicKey getRemoteStatic() {
			return publicKey;
		}

		public void send(OutgoingPeerPacket packet) throws IOException {
			channel.send(packet.transmissiblePacket().asByteBuffer(), routingGuard.remoteAddress());
		}

		@Override
		public void close() {
			routingGuard.close();
		}
	}
}
