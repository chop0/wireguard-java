package ax.xz.wireguard.spi;

import ax.xz.wireguard.device.PeerRoutingList;
import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.util.ServiceLoader;
import java.util.function.Supplier;

public interface WireguardRouterProvider {
	static WireguardRouterProvider provider() {
		return ServiceLoader.load(WireguardRouterProvider.class).stream()
			.map(Supplier::get).filter(WireguardRouterProvider::isAvailable).findFirst().orElseThrow();
	}

	boolean isAvailable();

	/**
	 * Creates a new WireguardRouter instance.
	 * @param fallbackPacketHandler a handler which will be called when a packet is received for which no channel matches
	 * @return
	 */
	WireguardRouter create(PeerRoutingList routingList);
}
