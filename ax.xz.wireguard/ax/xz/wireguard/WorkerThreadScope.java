package ax.xz.wireguard;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.concurrent.Callable;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.ThreadFactory;

public final class WorkerThreadScope extends StructuredTaskScope<Object> {
	private static final VarHandle FIRST_EXCEPTION;
	static {
		try {
			MethodHandles.Lookup l = MethodHandles.lookup();
			FIRST_EXCEPTION = l.findVarHandle(WorkerThreadScope.class, "firstException", Throwable.class);
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}
	private volatile Throwable firstException;

	public WorkerThreadScope(String name, ThreadFactory factory) {
		super(name, factory);
	}

	public WorkerThreadScope() {
		super();
	}

	@Override
	public <U> Subtask<U> fork(Callable<? extends U> task) {
		return super.fork(task);
	}

	public Subtask<Void> forkE(ExceptionRunnable task) {
		return fork(() -> {
			task.run();
			return null;
		});
	}

	public Subtask<Void> fork(Runnable task) {
		return fork(() -> {
			task.run();
			return null;
		});
	}

	@Override
	protected void handleComplete(Subtask<?> subtask) {
		if (subtask.state() == Subtask.State.FAILED
			&& firstException == null
			&& FIRST_EXCEPTION.compareAndSet(this, null, subtask.exception())) {
			subtask.exception().printStackTrace();
			super.shutdown();
		}
	}

	public interface ExceptionRunnable {
		void run() throws Exception;
	}
}
