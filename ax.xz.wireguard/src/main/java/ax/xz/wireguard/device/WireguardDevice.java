package ax.xz.wireguard.device;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.peer.PeerConnectionInfo;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.spi.WireguardRouter;
import ax.xz.wireguard.spi.WireguardRouterProvider;
import ax.xz.wireguard.util.SharedPool;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;

public final class WireguardDevice implements Closeable {
	private static final Logger log = System.getLogger(WireguardDevice.class.getName());

	private final NoisePrivateKey staticIdentity;

	private final PeerManager peerManager;
	private final UnmatchedPacketHandler fallbackHandler;

	private final PeerRoutingList routingList;

	private final WireguardRouter peerRouter;
	private final TunPacketRouter tunRouter;

	private final SharedPool bufferPool = new SharedPool(0x500);

	public WireguardDevice(NoisePrivateKey staticIdentity, Tun tun) {
		this.staticIdentity = staticIdentity;
		this.routingList = new PeerRoutingList();

		this.tunRouter = new TunPacketRouter(bufferPool, tun);
		this.peerRouter = WireguardRouterProvider.provider().create(routingList);

		this.peerManager = new PeerManager(staticIdentity, peerRouter, tunRouter);
		this.fallbackHandler = new UnmatchedPacketHandler(peerManager, routingList);

		peerRouter.configureFallbackHandler(fallbackHandler);
	}

	public void close() {
		peerManager.close();
		bufferPool.close();

		try {
			peerRouter.close();
			tunRouter.close();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException("Could not stop peer router", e);
		}
	}

	public void bind(InetSocketAddress endpoint) throws IOException {
		peerRouter.bind(endpoint);
		log.log(DEBUG, "Bound to {0}", endpoint);
	}

	public void addPeer(PeerConnectionInfo pci) {
		peerManager.startPeer(pci);
	}

	@Override
	public String toString() {
		return "Device[%s]".formatted(staticIdentity.publicKey().toString().substring(0, 8));
	}
}
