package ax.xz.wireguard;

import java.time.Instant;
import java.util.concurrent.Callable;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeoutException;

public class DelegatingStructuredTaskScope<T> extends StructuredTaskScope<T> {
	private final StructuredTaskScope<T> delegate;

	public DelegatingStructuredTaskScope(StructuredTaskScope<T> delegate) {
		super();
		this.delegate = delegate;
	}

	public DelegatingStructuredTaskScope(String name, ThreadFactory factory, StructuredTaskScope<T> delegate) {
		super(name, factory);
		this.delegate = delegate;
	}

	@Override
	public <U extends T> Subtask<U> fork(Callable<? extends U> task) {
		return delegate.fork(task);
	}

	@Override
	public StructuredTaskScope<T> join() throws InterruptedException {
		return delegate.join();
	}

	@Override
	public StructuredTaskScope<T> joinUntil(Instant deadline) throws InterruptedException, TimeoutException {
		return delegate.joinUntil(deadline);
	}

	@Override
	public void shutdown() {
		delegate.shutdown();
	}

	@Override
	public void close() {
		delegate.close();
	}

	@Override
	public String toString() {
		return delegate.toString();
	}
}
