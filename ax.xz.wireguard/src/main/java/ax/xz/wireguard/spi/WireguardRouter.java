package ax.xz.wireguard.spi;

import ax.xz.wireguard.device.PeerRoutingList;
import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public interface WireguardRouter extends AutoCloseable {
	void bind(InetSocketAddress address) throws IOException;
	void send(ByteBuffer buffer, InetSocketAddress address) throws IOException;

	PeerChannel openChannel(NoisePublicKey remoteKey, byte packetType);

	void configureFallbackHandler(FallbackPacketHandler handler);

	PeerRoutingList routingList();

	@Override
	void close() throws InterruptedException;

	interface FallbackPacketHandler {
		void handle(IncomingPeerPacket packet);
	}
}
