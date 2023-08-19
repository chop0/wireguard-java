package ax.xz.wireguard.device;

import org.slf4j.Logger;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.concurrent.StructuredTaskScope;
import java.util.function.Function;

/**
 * A {@link StructuredTaskScope} that logs and shuts down the executor if a task fails.
 */
public class PersistentTaskExecutor<E extends Exception> extends StructuredTaskScope<Void> {
	private static final VarHandle FIRST_EXCEPTION;
	static {
		try {
			FIRST_EXCEPTION = MethodHandles.lookup().findVarHandle(PersistentTaskExecutor.class, "firstException", Exception.class);
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private volatile Exception firstException;

	private final Function<Exception, E> exceptionMapper;
	private final Logger logger;

	public PersistentTaskExecutor(Function<Exception, E> exceptionMapper, Logger logger) {
		this.exceptionMapper = exceptionMapper;
		this.logger = logger;
	}

	@Override
	protected void handleComplete(Subtask<? extends Void> subtask) {
		super.handleComplete(subtask);

		if (subtask.state() == Subtask.State.FAILED && FIRST_EXCEPTION.compareAndSet(this, null, subtask.exception())) {
			logger.error("Persistent task failed", firstException);
			shutdown();
		}
	}

	public void submit(String taskName, InterruptibleRunnable task) {
		fork(() -> {
			Thread.currentThread().setName(taskName);
			try {
				task.run();
			} catch (InterruptedException e) {
				logger.warn("Persistent task interrupted");
				throw e;
			}

			return null;
		});
	}

	public void throwIfFailed() throws E {
		if (firstException != null)
			throw exceptionMapper.apply(firstException);
	}

	public interface InterruptibleRunnable {
		void run() throws InterruptedException;
	}
}