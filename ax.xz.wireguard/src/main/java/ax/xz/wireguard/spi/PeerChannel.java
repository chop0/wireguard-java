package ax.xz.wireguard.spi;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public interface PeerChannel extends AutoCloseable {
	InetSocketAddress receive(ByteBuffer buffer) throws IOException;
	void send(ByteBuffer buffer) throws IOException;

	void bind(byte packetType, int receiverIndex);
	void connect(InetSocketAddress remote);

	/**
	 * This class is always thread-safe, but sometimes, it's pointless to use multiple threads to receive packets.
	 * @return true if this channel supports receiving packets in parallel
	 */
	boolean supportsParallelReceive();
}
