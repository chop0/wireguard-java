package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.TunPacketRouter;
import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.transport.TransportPacket;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.spi.PeerChannel;
import ax.xz.wireguard.spi.WireguardRouter;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;

public class Peer implements AutoCloseable {
	private static final Logger logger = System.getLogger(Peer.class.getName());

	private final ExecutorService executor;

	private final SessionManager sessionManager;
	private final KeepaliveSender keepaliveSender;
	private final PeerTransportManager transportManager;

	private final PeerConnectionInfo pci;

	private final ExecutorService asyncPacketHandler = Executors.newVirtualThreadPerTaskExecutor();

	public Peer(TunPacketRouter.TunPacketChannel tunChannel, WireguardRouter router, PeerConnectionInfo pci) {
		this.pci = pci;

		PeerChannel transportChannel = null;
		try {
			transportChannel = router.openChannel(pci.handshakeDetails().remoteKey(), TransportPacket.TYPE);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		this.sessionManager = new SessionManager(pci, router, transportChannel);
		this.transportManager = new PeerTransportManager(sessionManager, pci.handshakeDetails().localIdentity(), pci.filter(), transportChannel, tunChannel);
		this.keepaliveSender = new KeepaliveSender(sessionManager, transportManager);

		this.executor = Executors.newThreadPerTaskExecutor(Thread.ofPlatform().uncaughtExceptionHandler((_, e) -> {
			logger.log(DEBUG, "Uncaught exception in peer {0}", Peer.this, e);
			Peer.this.executor.shutdown();
		}).name(pci.toString(), 0).factory());

		executor.submit(sessionManager);
		executor.submit(transportManager);
		executor.submit(keepaliveSender);
	}

	@Override
	public void close() {
		executor.shutdownNow();
		try {
			executor.awaitTermination(2, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException("Could not stop peer", e);
		}
	}

	public void handleAsync(IncomingPeerPacket packet) {
		switch (packet) {
			case IncomingInitiation initiation ->
				asyncPacketHandler.execute(() -> sessionManager.handleInitiation(initiation));
			case IncomingResponse response -> asyncPacketHandler.execute(() -> sessionManager.handleResponse(response));
			case UndecryptedIncomingTransport transport ->
				asyncPacketHandler.execute(() -> transportManager.handleIncomingTransport(transport));
		}
	}

	@Override
	public String toString() {
		return String.format("Peer{%s}", getAuthority());
	}

	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return "unknown";

		return session.toString();
	}

	public NoisePublicKey getRemoteStatic() {
		return pci.handshakeDetails().remoteKey();
	}

}
