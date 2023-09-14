package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.noise.handshake.Handshakes;

import javax.crypto.BadPaddingException;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * This class handles the handshake initiation process
 */
class HandshakeInitiator {
	private final Peer.PeerConnectionInfo connectionInfo;

	private final int localIndex;

	private final Handshakes.InitiatorStageOne handshake;
	private final WireguardDevice device;

	private HandshakeInitiator(WireguardDevice device, Peer.PeerConnectionInfo connectionInfo, int localIndex) throws IOException {
		this.device = requireNonNull(device);

		requireNonNull(connectionInfo.endpoint());
		this.connectionInfo = requireNonNull(connectionInfo);

		this.localIndex = localIndex;

		this.handshake = Handshakes.initiateHandshake(device.getStaticIdentity(), connectionInfo.remoteStatic(), connectionInfo.presharedKey());

		var packet = MessageInitiation.create(device.getBufferPool(), localIndex, handshake.getLocalEphemeral().publicKey(), handshake.getEncryptedStatic(), handshake.getEncryptedTimestamp());
		device.transmitNow(connectionInfo.endpoint(), packet.getSignedBuffer(connectionInfo.remoteStatic()));
	}

	public static HandshakeInitiator initiate(WireguardDevice device, Peer.PeerConnectionInfo connectionInfo, int localIndex) throws IOException {
		return new HandshakeInitiator(device, connectionInfo, localIndex);
	}

	private EstablishedSession session;
	public void consumeResponse(MessageResponse response) throws IOException {
		try {
			var kp = handshake.consumeMessageResponse(response.ephemeral(), response.encryptedEmpty());
			session = new EstablishedSession(device.getBufferPool(), kp, connectionInfo.endpoint(), response.sender(), connectionInfo.keepaliveInterval());
		} catch (BadPaddingException ex) {
			throw new IOException("Failed to decrypt response", ex);
		}
	}

	public EstablishedSession getSession() {
		requireNonNull(session, "consumeResponse must be called before getSession");

		return session;
	}
}
