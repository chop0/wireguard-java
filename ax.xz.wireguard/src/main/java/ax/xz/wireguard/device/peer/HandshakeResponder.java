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
	private final WireguardDevice device;

	private final int localIndex;

	private final Handshakes.ResponderHandshake handshake;
	private final EstablishedSession session;

	private HandshakeResponder(WireguardDevice device, MessageInitiation initiation, Duration keepaliveInterval, InetSocketAddress remoteAddress, int localIndex) throws IOException {
		requireNonNull(device);
		requireNonNull(initiation);

		this.device = device;
		this.localIndex = localIndex;

		try {
			this.handshake = Handshakes.responderHandshake(device.getStaticIdentity(), initiation.ephemeral(), initiation.encryptedStatic(), initiation.encryptedTimestamp());
		} catch (BadPaddingException ex) {
			throw new IOException("Failed to decrypt initiation", ex);
		}

		var packet = MessageResponse.create(localIndex, initiation.sender(), handshake.getLocalEphemeral(), handshake.getEncryptedEmpty(), handshake.getRemotePublicKey());
		device.transmit(remoteAddress, packet.buffer());

		this.session = new EstablishedSession(handshake.getKeypair(), remoteAddress, localIndex, initiation.sender(), keepaliveInterval);
	}

	public static EstablishedSession respond(WireguardDevice device, MessageInitiation initiation, Duration keepaliveInterval, InetSocketAddress remoteAddress, int localIndex) throws IOException {
		return new HandshakeResponder(device, initiation, keepaliveInterval, remoteAddress, localIndex).getSession();
	}

	public EstablishedSession getSession() {
		return session;
	}
}
