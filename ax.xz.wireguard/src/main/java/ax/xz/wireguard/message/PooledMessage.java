package ax.xz.wireguard.message;

import java.nio.ByteBuffer;

public abstract class PooledMessage {
	private final ByteBuffer bufferGuard;

	protected PooledMessage(int size, ByteBuffer bufferGuard) {
		if (bufferGuard.remaining() < size) {
			throw new IllegalArgumentException("Buffer is not big enough (expected %d, got %d)".formatted(size, bufferGuard.remaining()));
		}

		this.bufferGuard = bufferGuard;
	}

	public ByteBuffer buffer() {
		return bufferGuard.duplicate().order(bufferGuard.order());
	}
}
