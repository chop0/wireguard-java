package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.Pool;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.device.message.PacketElement;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;
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

public class Peer {
	private static final Logger logger = System.getLogger(Peer.class.getName());

	private final PeerConnectionInfo connectionInfo;

	private final SessionManager sessionManager;
	private final TransportManager transportManager;
	private final KeepaliveSender keepaliveSender;

	private final AtomicBoolean started = new AtomicBoolean(false);

	public Peer(WireguardDevice device, DatagramChannel channel, Pool pool, BlockingQueue<DecryptedIncomingTransport> interfaceBoundQueue, PeerConnectionInfo connectionInfo) {
		this.connectionInfo = connectionInfo;

		this.sessionManager = new SessionManager(device, channel, connectionInfo, pool);
		this.transportManager = new TransportManager(sessionManager, pool, interfaceBoundQueue);
		this.keepaliveSender = new KeepaliveSender(sessionManager, transportManager);
	}

	public void start() throws InterruptedException {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		logger.log(DEBUG, "Started peer {0}", this);

		try (var executor = Executors.newThreadPerTaskExecutor(Thread.ofPlatform().factory())) {
			executor.submit(sessionManager);
			executor.submit(transportManager);
			executor.submit(keepaliveSender);

			executor.awaitTermination(999_999_999, TimeUnit.DAYS);
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

	public void sendTransportMessage(ReferenceCounted<PacketElement.IncomingTunnelPacket> guard) {
		transportManager.sendOutgoingTransport(guard);
	}

	@Override
	public String toString() {
		return String.format("Peer{%s, pubkey %s}", getAuthority(), connectionInfo.remoteStatic.toString().substring(0, 8));
	}

	@Override
	public int hashCode() {
		return connectionInfo.remoteStatic.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof Peer peer) {
			return connectionInfo.remoteStatic.equals(peer.connectionInfo.remoteStatic);
		} else {
			return false;
		}
	}

	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	public record PeerConnectionInfo(NoisePrivateKey localStaticIdentity, NoisePublicKey remoteStatic,
									 @Nullable NoisePresharedKey presharedKey,
									 @Nullable InetSocketAddress endpoint, Duration keepaliveInterval) {
		public PeerConnectionInfo {
			requireNonNull(remoteStatic);

			if (keepaliveInterval == null)
				keepaliveInterval = Duration.ofDays(1_000_000_000);

			if (presharedKey == null)
				presharedKey = NoisePresharedKey.zero();
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
