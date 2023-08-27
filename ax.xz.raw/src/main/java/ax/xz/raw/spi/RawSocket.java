package ax.xz.raw.spi;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * A raw socket can send and receive L3 packets.  It is not bound to a specific protocol, and can be used to send and receive any kind of
 * packet.
 *
 * @see RawSocketProvider
 * @see TunProvider
 */
public interface RawSocket extends Closeable {
	void write(ByteBuffer buffer) throws IOException;
	void read(ByteBuffer buffer) throws IOException;
}
