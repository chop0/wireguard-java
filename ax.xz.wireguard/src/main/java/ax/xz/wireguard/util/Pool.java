package ax.xz.wireguard.util;

import ax.xz.wireguard.device.message.PacketElement;

import java.lang.foreign.Arena;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.concurrent.ConcurrentLinkedQueue;

public class Pool implements AutoCloseable {
	private static final int TCACHE_SIZE = 7;

	private static final VarHandle POOL_SIZE, NUM_ALLOCATED, NUM_RELEASED;

	static {
		try {
			POOL_SIZE = MethodHandles.lookup().findVarHandle(Pool.class, "poolSize", int.class);
			NUM_ALLOCATED = MethodHandles.lookup().findVarHandle(Pool.class, "numberAllocated", int.class);
			NUM_RELEASED = MethodHandles.lookup().findVarHandle(Pool.class, "numberReleased", int.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private static final System.Logger logger = System.getLogger(Pool.class.getSimpleName());

	private final int maxPoolSize;

	private final ConcurrentLinkedQueue<PacketElement.Uninitialised> pool;
	private final ThreadLocal<PacketElement.Uninitialised[]> tcache = ThreadLocal.withInitial(() -> new PacketElement.Uninitialised[TCACHE_SIZE]);

	private final Arena arena = Arena.ofAuto();

	private volatile int poolSize = 0;
	private volatile int numberAllocated = 0;
	private volatile int numberReleased = 0;

	public Pool(int maxPoolSize) {
		this.maxPoolSize = maxPoolSize;
		this.pool = new ConcurrentLinkedQueue<>();
	}

	private PacketElement.Uninitialised retrieveTcacheIfAvailable() {
		var tcache = this.tcache.get();
		for (int i = 0; i < TCACHE_SIZE; i++) {
			var item = tcache[i];
			if (item != null) {
				tcache[i] = null;
				return item;
			}
		}

		return null;
	}

	private boolean storeTcacheIfAvailable(PacketElement.Uninitialised item) {
		var tcache = this.tcache.get();
		for (int i = 0; i < TCACHE_SIZE; i++) {
			if (tcache[i] == null) {
				tcache[i] = item;
				return true;
			}
		}

		return false;
	}

	/**
	 * Acquire a item from the pool. If the pool is empty, a new item is allocated.
	 * If the needed size is larger than the pool's item size, a warning is logged and a new item is allocated.
	 *
	 * @return A item of at least the requested size
	 */
	public PacketElement.Uninitialised acquire() {
		var result = acquire0();
		return result;
	}

	private PacketElement.Uninitialised acquire0() {
		var tcacheItem = retrieveTcacheIfAvailable();
		if (tcacheItem != null)
			return tcacheItem;

		var pollItem = pool.poll();
		if (pollItem != null) {
			POOL_SIZE.getAndAdd(this, -1);
			return pollItem;
		}

		NUM_ALLOCATED.getAndAdd(this, 1);
//		logger.log(DEBUG, "Item pool empty, allocating new item (allocated {0}, released {1})", numberAllocated, numberReleased);
		return new PacketElement.Uninitialised(arena.allocate(4096), p -> release(PacketElement.Uninitialised.ofMoved(p)));
	}

	private void release(PacketElement.Uninitialised item) {
		if (storeTcacheIfAvailable(item))
			return;

		if (poolSize + 1 > maxPoolSize) {
//			logger.log(DEBUG, "Item pool full, discarding item (allocated {0}, released {1})", numberAllocated, numberReleased);
			return;
		}

		pool.offer(item);
		NUM_RELEASED.getAndAdd(this, 1);
		POOL_SIZE.getAndAdd(this, 1);
	}

	@Override
	public void close() {
		pool.clear();
	}
}
