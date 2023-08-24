package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.Message;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.annotation.Nullable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.WARNING;
import static java.util.Objects.requireNonNull;

public class Peer {
	public static final ScopedValue<Peer> PEER = ScopedValue.newInstance();

	private static final Logger logger = System.getLogger(Peer.class.getName());

	// Instance variables
	private final PeerConnectionInfo connectionInfo;

	private final SessionManager sessionManager;
	private final WireguardDevice device;

	private final AtomicBoolean started = new AtomicBoolean(false);

	public Peer(WireguardDevice device, PeerConnectionInfo connectionInfo) {
		this.connectionInfo = connectionInfo;
		this.device = device;

		this.sessionManager = new SessionManager(device, connectionInfo);
		logger.log(DEBUG, "Created peer {0}", this);
	}

	public void start() throws IOException {
		if (!started.compareAndSet(false, true)) {
			throw new IllegalStateException("Peer already started");
		}

		ScopedValue.runWhere(PEER, this, sessionManager::run);
	}

	/**
	 * Removes a decrypted transport message from the queue, and waits if none is present
	 *
	 * @return decrypted transport packet received
	 * @throws InterruptedException if the thread is interrupted whilst waiting
	 */
	public ByteBuffer readTransportPacket() throws InterruptedException {
		return sessionManager.receiveDecryptedTransport();
	}

	public NoisePublicKey getRemoteStatic() {
		return connectionInfo.remoteStatic;
	}

	public void receiveInboundMessage(InetSocketAddress address, Message message) {
		switch (message) {
			case MessageTransport transport -> sessionManager.receiveTransport(transport);
			case MessageInitiation initiation -> sessionManager.receiveInitiation(address, initiation);
			case MessageResponse response -> sessionManager.receiveHandshakeResponse(response);
			default -> logger.log(WARNING, "Received unexpected message type: {0}", message);
		}
	}

	@Override
	public String toString() {
		return String.format("Peer{%s, pubkey %s}", getAuthority(), connectionInfo.remoteStatic.toString().substring(0, 8));
	}

	public String getAuthority() {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			if (connectionInfo.endpoint != null) {
				return connectionInfo.endpoint.getHostString();
			} else
				return "unknown";

		return session.getOutboundPacketAddress().toString();
	}

	/**
	 * Sends the given transport data to the peer.
	 * @param data data to send
	 * @throws IOException if no session is established or something is wrong with the socket
	 */
	public int writeTransportPacket(ByteBuffer data) throws IOException {
		var session = sessionManager.tryGetSessionNow();
		if (session == null)
			throw new IOException("No session established");

		return session.sendTransportPacket(device, data);
	}

	record TransportWithSession(MessageTransport transport, EstablishedSession session) {
	}

	public record PeerConnectionInfo(NoisePublicKey remoteStatic, @Nullable NoisePresharedKey presharedKey, @Nullable InetSocketAddress endpoint, Duration keepaliveInterval) {
		public PeerConnectionInfo {
			requireNonNull(remoteStatic);
			requireNonNull(keepaliveInterval);

			if (presharedKey == null)
				presharedKey = NoisePresharedKey.zero();
		}
	}
}
