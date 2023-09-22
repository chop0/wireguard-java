package ax.xz.wireguard.util;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

/**
 * A reference-counted wrapper around an {@link AutoCloseable}. When the reference count reaches zero, the object is closed.
 *
 * @param <T>
 */
public class ReferenceCounted<T extends AutoCloseable> implements AutoCloseable {
	private static final VarHandle CLOSED;

	static {
		try {
			CLOSED = MethodHandles.lookup().findVarHandle(ReferenceCounted.class, "closed", boolean.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private final RcInner<T> object;
	private volatile boolean closed = false;

	private ReferenceCounted(RcInner<T> object) {
		if (object.closed)
			throw new IllegalStateException("Object already closed");

		this.object = object;
	}

	/**
	 * Returns the wrapped object.
	 *
	 * @return the wrapped object
	 */
	public T get() {
		if (closed) {
			throw new IllegalStateException("Guard already closed");
		}

		return object.object;
	}

	/**
	 * Increments the reference count of this object and returns a new copy of this object
	 */
	public ReferenceCounted<T> retain() {
		object.retain();
		return new ReferenceCounted<>(object);
	}

	/**
	 * Creates a new reference-counted wrapper around the given object with a reference count of 1.
	 *
	 * @param object the object to wrap
	 * @param <T>    the type of the object
	 * @return a new reference-counted wrapper around the given object
	 */
	public static <T extends AutoCloseable> ReferenceCounted<T> of(T object) {
		return new ReferenceCounted<>(new RcInner<>(object));
	}

	/**
	 * Closes this guard and decrements the reference count of the object. If the reference count reaches zero, the object is closed.
	 */
	@Override
	public void close() {
		if (!CLOSED.compareAndSet(this, false, true)) {
			throw new IllegalStateException("Object already closed");
		}

		object.release();
	}

	private static class RcInner<T extends AutoCloseable> {
		private static final VarHandle REF_COUNT, CLOSED;

		static {
			try {
				REF_COUNT = MethodHandles.lookup().findVarHandle(RcInner.class, "refCount", int.class);
				CLOSED = MethodHandles.lookup().findVarHandle(RcInner.class, "closed", boolean.class);
			} catch (ReflectiveOperationException e) {
				throw new ExceptionInInitializerError(e);
			}
		}

		private final T object;
		private volatile int refCount = 1;
		private volatile boolean closed = false;

		private RcInner(T object) {
			this.object = object;
		}

		private void retain() {
			if (closed) {
				throw new IllegalStateException("Object already closed");
			}

			REF_COUNT.getAndAdd(this, 1);
		}

		private void release() {
			if (closed) {
				throw new IllegalStateException("Object already closed");
			}

			if ((int) REF_COUNT.getAndAdd(this, -1) <= 1) {
				try {
					object.close();
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
				closed = true;
			}
		}
	}
}
