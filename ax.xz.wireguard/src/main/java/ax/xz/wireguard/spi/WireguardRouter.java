package ax.xz.wireguard.spi;

import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public interface WireguardRouter extends AutoCloseable {
	void bind(InetSocketAddress address) throws IOException;

	default void send(SendRequest... requests) throws IOException {
		for (SendRequest request : requests) {
			send(request.segment().asByteBuffer(), request.address());
		}
	}

	void send(ByteBuffer buffer, InetSocketAddress address) throws IOException;

	PeerChannel openChannel(NoisePublicKey remoteKey, byte packetType) throws IOException;

	void configureInitiationHandler(InitiationHandler handler);

	int shuffleIndex(NoisePublicKey remoteKey);

	@Override
	void close() throws InterruptedException;

	interface InitiationHandler {
		void handle(IncomingInitiation initiation);
	}

	record SendRequest(MemorySegment segment, InetSocketAddress address) {
	}
}
