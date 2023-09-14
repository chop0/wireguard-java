package ax.xz.wireguard.util;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.function.Function;

/**
 * A {@link StructuredTaskScope} that logs and shuts down the executor if a task fails.
 */
public class PersistentTaskExecutor<E extends Throwable> extends ThreadPoolExecutor {
	private static final VarHandle FIRST_EXCEPTION;
	static {
		try {
			FIRST_EXCEPTION = MethodHandles.lookup().findVarHandle(PersistentTaskExecutor.class, "firstException", Throwable.class);
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	@SuppressWarnings("unused")
	private volatile Throwable firstException;

	private final Function<? super Throwable, ? extends E> exceptionMapper;
	private final Logger logger;

	public PersistentTaskExecutor(Function<? super Throwable, ? extends E> exceptionMapper, Logger logger, ThreadFactory threadFactory) {
		super(0, Integer.MAX_VALUE, 0, TimeUnit.NANOSECONDS, new SynchronousQueue<>(), threadFactory);
		this.exceptionMapper = exceptionMapper;
		this.logger = logger;
	}

	public void submit(String taskName, InterruptibleRunnable task) {
		submit(() -> {
			Thread.currentThread().setName(taskName);
			try {
				task.run();
			} catch (InterruptedException e) {
				logger.log(WARNING, "Persistent task interrupted");
				Thread.currentThread().interrupt();
			} catch (Throwable e) {
				logger.log(WARNING, "Persistent task failed", e);
				FIRST_EXCEPTION.compareAndSet(this, null, e);
			}
		});
	}

	public void throwIfFailed() throws E {
		if (firstException != null)
			throw exceptionMapper.apply(firstException);
	}

	public void awaitTermination() throws InterruptedException {
		awaitTermination(Long.MAX_VALUE, TimeUnit.MILLISECONDS);
	}

	public void awaitTermination(Duration timeout) throws InterruptedException {
		awaitTermination(timeout.toMillis(), TimeUnit.MILLISECONDS);
	}

	public interface InterruptibleRunnable {
		void run() throws InterruptedException;
	}
}
