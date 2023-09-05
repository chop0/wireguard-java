package ax.xz.packet;

import java.nio.ByteBuffer;

public interface L3Packet {
	void write(ByteBuffer buf);
	int size();
}
