package ax.xz.wireguard.device;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.peer.PeerConnectionInfo;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.Pool;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;

public final class WireguardDevice implements Closeable {
	// for debugging performance, so flamegraphs look nicer
	public static final boolean SYNCRONOUS_PIPELINE = false;

	private static final Logger log = System.getLogger(WireguardDevice.class.getName());

	private final NoisePrivateKey staticIdentity;

	private final PeerManager peerManager;

	private final PeerPacketRouter peerRouter;
	private final TunPacketRouter tunRouter;

	private final Pool bufferPool = new Pool(0x500);

	public WireguardDevice(NoisePrivateKey staticIdentity, Tun tun) {
		this.staticIdentity = staticIdentity;

		try {
			this.tunRouter = new TunPacketRouter(bufferPool, tun);
			this.peerRouter = new PeerPacketRouter(bufferPool, staticIdentity, this::setupChannelDownstream);
			this.peerManager = new PeerManager(bufferPool, staticIdentity, tunRouter);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private void setupChannelDownstream(NoisePublicKey noisePublicKey, PeerPacketRouter.PeerPacketChannel channel) {
		peerManager.setupChannelDownstream(noisePublicKey, channel);
	}

	public void run() {
		try (var executor = Executors.newThreadPerTaskExecutor(Thread.ofPlatform().factory())) {
			executor.submit(peerRouter);
			executor.submit(tunRouter);

			executor.awaitTermination(999_999_999, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			log.log(DEBUG, "Wireguard device interrupted");
		} finally {
			close();
		}
	}

	public void close() {
		bufferPool.close();
		peerManager.close();
	}

	public void bind(InetSocketAddress endpoint) throws IOException {
		peerRouter.bind(endpoint);
		log.log(DEBUG, "Bound to {0}", endpoint);
	}

	public void addPeer(PeerConnectionInfo pci) {
		peerManager.addPeer(pci);
		peerRouter.maybeCreatePeer(pci.handshakeDetails().remoteKey());
	}

	@Override
	public String toString() {
		return "Device[%s]".formatted(staticIdentity.publicKey().toString().substring(0, 8));
	}
}
