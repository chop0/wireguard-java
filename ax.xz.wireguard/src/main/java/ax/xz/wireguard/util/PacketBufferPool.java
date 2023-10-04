package ax.xz.wireguard.util;

import ax.xz.wireguard.device.message.PacketElement;

public interface PacketBufferPool extends AutoCloseable {
	/**
	 * Acquire a item from the pool. If the pool is empty, a new item is allocated.
	 * If the needed size is larger than the pool's item size, a warning is logged and a new item is allocated.
	 *
	 * @return A item of at least the requested size
	 */
	PacketElement.Uninitialised acquire();

	@Override
	void close();

	static PacketBufferPool local(int maxPoolSize) {
		return ThreadLocalPool.of(maxPoolSize);
	}

	static PacketBufferPool shared(int maxPoolSize) {
		return SharedPool.of(maxPoolSize);
	}
}
