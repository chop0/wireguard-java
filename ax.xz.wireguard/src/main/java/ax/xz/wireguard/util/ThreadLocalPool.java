package ax.xz.wireguard.util;

import ax.xz.wireguard.device.message.PacketElement;

import java.lang.foreign.Arena;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.LinkedList;
import java.util.concurrent.ConcurrentLinkedQueue;

public class ThreadLocalPool implements PacketBufferPool {
	private static final VarHandle POOL_SIZE, NUM_ALLOCATED, NUM_RELEASED;

	static {
		try {
			POOL_SIZE = MethodHandles.lookup().findVarHandle(ThreadLocalPool.class, "poolSize", int.class);
			NUM_ALLOCATED = MethodHandles.lookup().findVarHandle(ThreadLocalPool.class, "numberAllocated", int.class);
			NUM_RELEASED = MethodHandles.lookup().findVarHandle(ThreadLocalPool.class, "numberReleased", int.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private final int maxPoolSize;

	private final LinkedList<PacketElement.Uninitialised> pool;
	private final Arena arena = Arena.ofAuto();

	private volatile int poolSize = 0;
	private volatile int numberAllocated = 0;
	private volatile int numberReleased = 0;

	public ThreadLocalPool(int maxPoolSize) {
		this.maxPoolSize = maxPoolSize;
		this.pool = new LinkedList<>();
	}

	public static ThreadLocalPool of(int maxPoolSize) {
		return new ThreadLocalPool(maxPoolSize);
	}

	@Override
	public PacketElement.Uninitialised acquire() {
		var result = acquire0();
		return result;
	}

	private PacketElement.Uninitialised acquire0() {
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
