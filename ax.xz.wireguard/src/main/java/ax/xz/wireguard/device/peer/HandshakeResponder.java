package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.noise.handshake.Handshakes;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * This class handles the handshake initiation process
 */
class HandshakeResponder {

	private final Handshakes.ResponderHandshake handshake;
	private final EstablishedSession session;

	private HandshakeResponder(WireguardDevice device, MessageInitiation initiation, Duration keepaliveInterval, InetSocketAddress remoteAddress, int localIndex) throws IOException {
		requireNonNull(device);
		requireNonNull(initiation);

		try {
			this.handshake = Handshakes.responderHandshake(device.getStaticIdentity(), initiation.ephemeral(), initiation.encryptedStatic(), initiation.encryptedTimestamp());
		} catch (BadPaddingException ex) {
			throw new IOException("Failed to decrypt initiation", ex);
		}

		var packet = MessageResponse.create(device.getBufferPool(), localIndex, initiation.sender(), handshake.getLocalEphemeral(), handshake.getEncryptedEmpty(), handshake.getRemotePublicKey());
		device.transmitNow(remoteAddress, packet.bufferGuard());

		this.session = new EstablishedSession(device.getBufferPool(), handshake.getKeypair(), remoteAddress, initiation.sender(), keepaliveInterval);
	}

	public static EstablishedSession respond(WireguardDevice device, MessageInitiation initiation, Duration keepaliveInterval, InetSocketAddress remoteAddress, int localIndex) throws IOException {
		return new HandshakeResponder(device, initiation, keepaliveInterval, remoteAddress, localIndex).getSession();
	}

	public EstablishedSession getSession() {
		return session;
	}
}