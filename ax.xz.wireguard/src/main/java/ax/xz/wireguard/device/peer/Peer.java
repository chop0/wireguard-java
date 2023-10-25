package ax.xz.wireguard.device.peer;

import ax.xz.raw.spi.BatchedDatagramSocket;
import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.Pool;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.util.IPFilter;
import ax.xz.wireguard.util.ReferenceCounted;

import javax.annotation.Nullable;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;
import static java.util.Objects.requireNonNull;

public class Peer implements Runnable {
	private static final Logger logger = System.getLogger(Peer.class.getName());

	private final PeerConnectionInfo connectionInfo;

	private final SessionManager sessionManager;
	private final TransportManager transportManager;
	private final KeepaliveSender keepaliveSender;

	private final AtomicBoolean started = new AtomicBoolean(false);

	public Peer(WireguardDevice device, NoisePrivateKey localIdentity, DatagramChannel channel, Pool pool, Tun tun, PeerConnectionInfo connectionInfo) {
		this.connectionInfo = connectionInfo;

		this.sessionManager = new SessionManager(device, channel, connectionInfo, localIdentity, pool);
		this.transportManager = new TransportManager(connectionInfo.filter, sessionManager, pool, tun);
		this.keepaliveSender = new KeepaliveSender(sessionManager, transportManager);
	}

	public void run() {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		logger.log(DEBUG, "Started peer {0}", this);

		try (var executor = Executors.newThreadPerTaskExecutor(Thread.ofPlatform().factory())) {
			executor.submit(sessionManager);
			executor.submit(transportManager);
			executor.submit(keepaliveSender);

			executor.awaitTermination(999_999_999, TimeUnit.DAYS);
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Peer {0} interrupted", this);
		} finally {
			logger.log(DEBUG, "Stopped peer {0}", this);
		}
	}

	public NoisePublicKey getRemoteStatic() {
		return connectionInfo.remoteStatic;
	}

	public void routeMessage(IncomingPeerPacket message) {
		switch (message) {
			case IncomingResponse rp -> sessionManager.handleResponse(rp);
			case IncomingInitiation ip -> sessionManager.handleInitiation(ip);
			case UndecryptedIncomingTransport tp -> transportManager.handleIncomingTransport(tp);
		}
	}

	public void sendTransportMessage(ReferenceCounted<IncomingTunnelPacket> guard) {
		transportManager.sendOutgoingTransport(guard);
	}

	@Override
	public String toString() {
		return String.format("Peer{%s, pubkey %s}", getAuthority(), connectionInfo.remoteStatic.toString().substring(0, 8));
	}

	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	public record PeerConnectionInfo(
		NoisePublicKey remoteStatic,
		NoisePresharedKey presharedKey,

		@Nullable InetSocketAddress endpoint,
		Duration keepaliveInterval,

		IPFilter filter
	) {
		public PeerConnectionInfo {
			requireNonNull(remoteStatic);

			if (keepaliveInterval == null)
				keepaliveInterval = Duration.ofDays(1_000_000_000);

			if (presharedKey == null)
				presharedKey = NoisePresharedKey.zero();
		}

		public static PeerConnectionInfo of(NoisePublicKey remoteStatic) {
			return new PeerConnectionInfo(
				remoteStatic,
				NoisePresharedKey.zero(),
				null,
				Duration.ofDays(1_000_000_000),
				IPFilter.allowingAll()
			);
		}

		@Override
		public String toString() {
			if (endpoint != null)
				return endpoint.toString();
			else
				return remoteStatic.toString().substring(0, 8);
		}
	}
}
