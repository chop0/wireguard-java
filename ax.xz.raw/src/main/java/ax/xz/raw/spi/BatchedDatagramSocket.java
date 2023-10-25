package ax.xz.raw.spi;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.stream.Stream;

public interface BatchedDatagramSocket extends AutoCloseable {
	void send(Collection<Packet> packets) throws IOException;
	int receive(Collection<Packet> packets) throws IOException;

	void bind(InetSocketAddress address) throws IOException;

	@Override
	void close();

	record Packet(InetSocketAddress dst, MemorySegment... segment) {}
}
