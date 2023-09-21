package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.message.initiation.OutgoingInitiation;
import ax.xz.wireguard.device.message.response.OutgoingResponse;
import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;

/**
 * A packet coming in from another peer
 */
public sealed interface OutgoingPeerPacket extends AutoCloseable permits OutgoingInitiation, OutgoingResponse, EncryptedOutgoingTransport {
	long length();
	MemorySegment transmissiblePacket();

	@Override
	void close();
}
