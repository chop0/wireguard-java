package ax.xz.wireguard.device.peer;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.PeerPacketRouter;
import ax.xz.wireguard.device.TunPacketRouter;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.util.Pool;
import ax.xz.wireguard.util.ReferenceCounted;

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;

public class Peer implements AutoCloseable {
	private static final Logger logger = System.getLogger(Peer.class.getName());

	private final SessionManager sessionManager;
	private final PeerTransportManager peerTransportManager;
	private final KeepaliveSender keepaliveSender;

	private final Thread peerThread;
	private final PeerPacketRouter.PeerPacketChannel peerChannel;

	private final AtomicBoolean started = new AtomicBoolean(false);

	public Peer(Pool pool, PeerPacketRouter.PeerPacketChannel peerChannel, TunPacketRouter.TunPacketChannel tunChannel, PeerConnectionInfo pci) {
		this.peerChannel = peerChannel;

		this.sessionManager = new SessionManager(pool, peerChannel, pci);
		this.peerTransportManager = new PeerTransportManager(pool, peerChannel, tunChannel, pci, sessionManager);
		this.keepaliveSender = new KeepaliveSender(sessionManager, peerTransportManager);

		this.peerThread = Thread.ofVirtual().name(toString()).start(this::run);
	}

	private void run() {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		logger.log(DEBUG, "Started peer {0}", this);

		try (var executor = Executors.newThreadPerTaskExecutor(Thread.ofPlatform().factory())) {
			executor.submit(sessionManager);
			executor.submit(peerTransportManager);
			executor.submit(keepaliveSender);

			executor.awaitTermination(999_999_999, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Peer {0} interrupted", this);
		} finally {
			logger.log(DEBUG, "Stopped peer {0}", this);
			close();
		}
	}

	public void sendTransportMessage(ReferenceCounted<IncomingTunnelPacket> guard) {
		peerTransportManager.sendOutgoingTransport(guard);
	}

	@Override
	public String toString() {
		return String.format("Peer{%s}", getAuthority());
	}

	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	@Override
	public void close() {
		peerChannel.close();
		peerThread.interrupt();
		try {
			peerThread.join(Duration.ofSeconds(2));
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new RuntimeException("Could not stop peer", e);
		}
	}

}
