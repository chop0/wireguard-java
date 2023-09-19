package ax.xz.wireguard.device;

import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentLinkedQueue;

import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.WARNING;

public class BufferPool implements AutoCloseable {
	private static final int TCACHE_SIZE = 7;

	private static final VarHandle POOL_SIZE, NUM_ALLOCATED, NUM_RELEASED;

	static {
		try {
			POOL_SIZE = MethodHandles.lookup().findVarHandle(BufferPool.class, "poolSize", int.class);
			NUM_ALLOCATED = MethodHandles.lookup().findVarHandle(BufferPool.class, "numberAllocated", int.class);
			NUM_RELEASED = MethodHandles.lookup().findVarHandle(BufferPool.class, "numberReleased", int.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private static final System.Logger logger = System.getLogger(BufferPool.class.getSimpleName());

	private final int bufferSize;
	private final int maxPoolSize;

	private final ConcurrentLinkedQueue<ByteBuffer> pool;
	private final ThreadLocal<ByteBuffer[]> tcache = ThreadLocal.withInitial(() -> new ByteBuffer[TCACHE_SIZE]);

	private volatile int poolSize = 0;
	private volatile int numberAllocated = 0;
	private volatile int numberReleased = 0;

	public BufferPool(int bufferSize, int startingPoolSize, int maxPoolSize) {
		this.bufferSize = bufferSize;
		this.maxPoolSize = maxPoolSize;

		if (startingPoolSize > maxPoolSize)
			throw new IllegalArgumentException("Starting pool size cannot be larger than max pool size");

		this.pool = new ConcurrentLinkedQueue<>();
		for (int i = 0; i < startingPoolSize; i++) {
			pool.offer(ByteBuffer.allocateDirect(bufferSize));
			POOL_SIZE.getAndAdd(this, 1);
		}
	}

	private ByteBuffer retrieveTcacheIfAvailable() {
		var tcache = this.tcache.get();
		for (int i = 0; i < TCACHE_SIZE; i++) {
			var buffer = tcache[i];
			if (buffer != null) {
				tcache[i] = null;
				return buffer;
			}
		}

		return null;
	}

	private boolean storeTcacheIfAvailable(ByteBuffer buffer) {
		var tcache = this.tcache.get();
		for (int i = 0; i < TCACHE_SIZE; i++) {
			if (tcache[i] == null) {
				tcache[i] = buffer;
				return true;
			}
		}

		return false;
	}

	/**
	 * Acquire a buffer from the pool. If the pool is empty, a new buffer is allocated.
	 * If the needed size is larger than the pool's buffer size, a warning is logged and a new buffer is allocated.
	 *
	 * @param neededSize The minimum size of the buffer
	 * @return A buffer of at least the requested size
	 */
	public BufferGuard acquire(int neededSize) {
		return new BufferGuard(acquire0(neededSize).limit(neededSize), this);
	}

	private ByteBuffer acquire0(int neededSize) {
		if (neededSize > bufferSize) {
			logger.log(WARNING, "Requested buffer size %d is larger than pool size %d", neededSize, bufferSize);
			return ByteBuffer.allocateDirect(neededSize);
		}

		var tcacheBuffer = retrieveTcacheIfAvailable();
		if (tcacheBuffer != null)
			return tcacheBuffer;

		var pollBuffer = pool.poll();
		if (pollBuffer != null) {
			POOL_SIZE.getAndAdd(this, -1);
			return pollBuffer;
		}

		NUM_ALLOCATED.getAndAdd(this, 1);
		logger.log(DEBUG, "Buffer pool empty, allocating new buffer (allocated {0}, released {1})", numberAllocated, numberReleased);
		return ByteBuffer.allocateDirect(bufferSize);
	}

	private void release(ByteBuffer buffer) {
		buffer.clear();

		if (storeTcacheIfAvailable(buffer))
			return;

		if (poolSize + 1 > maxPoolSize) {
			logger.log(DEBUG, "Buffer pool full, discarding buffer (allocated {0}, released {1})", numberAllocated, numberReleased);
			return;
		}

		pool.offer(buffer);
		NUM_RELEASED.getAndAdd(this, 1);
		POOL_SIZE.getAndAdd(this, 1);
	}

	@Override
	public void close() {
		pool.clear();
	}

	public static ByteBuffer empty() {
		interface EmptyBuffer {
			ByteBuffer EMPTY = ByteBuffer.allocateDirect(0);
		}

		return EmptyBuffer.EMPTY.duplicate();
	}

	public static final class BufferGuard implements AutoCloseable {
		private static final VarHandle CLOSED;

		static {
			try {
				CLOSED = MethodHandles.lookup().findVarHandle(BufferGuard.class, "closed", boolean.class);
			} catch (ReflectiveOperationException e) {
				throw new ExceptionInInitializerError(e);
			}
		}

		private final ByteBuffer buffer;
		private final BufferPool pool;

		private volatile boolean closed = false;

		public BufferGuard(ByteBuffer buffer, BufferPool pool) {
			this.buffer = buffer;
			this.pool = pool;
		}

		@Override
		public void close() {
			if (!CLOSED.compareAndSet(this, false, true))
				throw new IllegalStateException("Buffer already closed");

			pool.release(buffer);
		}

		@Override
		public BufferGuard clone() {
			if (closed)
				throw new IllegalStateException("Buffer already closed");

			var newBuffer = pool.acquire(buffer.capacity());
			newBuffer.buffer().put(buffer.duplicate().clear());
			newBuffer.buffer().position(buffer.position());
			newBuffer.buffer().limit(buffer.limit());
			newBuffer.buffer().order(buffer.order());

			return newBuffer;
		}

		public ByteBuffer buffer() {
			if (closed)
				throw new IllegalStateException("Buffer already closed");
			return buffer;
		}

		public MemorySegment segment() {
			if (closed)
				throw new IllegalStateException("Buffer already closed");
			return MemorySegment.ofBuffer(buffer);
		}

		public BufferPool pool() {
			return pool;
		}
	}
}
