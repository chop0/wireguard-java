package ax.xz.wireguard.device;

import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.spi.WireguardRouter;

import static java.lang.System.Logger.Level.DEBUG;

/**
 * <h4>This class receives peer traffic and sends port-specific outbound traffic to peers.</h4>
 *
 * <p>
 * 'port-specific' includes handshake initiation messages and responses, but not transport packets;  WireGuard
 * does not use IP addresses (or ports) to route packets or identify clients after the handshake is complete.
 * </p>
 */
public class UnmatchedPacketHandler implements WireguardRouter.FallbackPacketHandler {
	private static final System.Logger log = System.getLogger(UnmatchedPacketHandler.class.getName());

	private final PeerManager peerManager;
	private final PeerRoutingList routingList;

	public UnmatchedPacketHandler(PeerManager peerManager, PeerRoutingList routingList) {
		this.peerManager = peerManager;
		this.routingList = routingList;
	}

	public void handle(IncomingPeerPacket packet) {
		var peer = getMessageDestination(packet);
		if (peer == null) {
			log.log(DEBUG, "Received message from unknown peer {0}", peer);
			return;
		}

		peer.handleAsync(packet);
	}

	private Peer getMessageDestination(IncomingPeerPacket packet) {
		return switch (packet) {
			case IncomingInitiation initiation -> peerManager.getOrAdd(initiation.remotePublicKey());
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
}
