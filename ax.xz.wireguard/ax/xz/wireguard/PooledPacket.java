package ax.xz.wireguard;

import java.nio.ByteBuffer;

public abstract class PooledPacket {
	private final ByteBuffer bufferGuard;
	private final int size;

	protected PooledPacket(int size, ByteBuffer bufferGuard) {
		if (bufferGuard.remaining() < size) {
			throw new IllegalArgumentException("Buffer is not big enough (expected %d, got %d)".formatted(size, bufferGuard.remaining()));
		}

		this.size = size;
		this.bufferGuard = bufferGuard;
	}

	protected ByteBuffer buffer() {
		return bufferGuard.duplicate().order(bufferGuard.order());
	}
}
