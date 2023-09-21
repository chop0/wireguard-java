package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.transport.incoming.UndecryptedIncomingTransport;

import java.net.InetSocketAddress;

/**
 * A packet coming in from another peer
 */
public sealed interface IncomingPeerPacket extends AutoCloseable permits IncomingInitiation, IncomingResponse, UndecryptedIncomingTransport {
	InetSocketAddress originAddress();

	long length();

	@Override
	void close();
}
