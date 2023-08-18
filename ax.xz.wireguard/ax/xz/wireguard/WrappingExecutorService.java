package ax.xz.wireguard;

import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

public abstract class WrappingExecutorService extends AbstractExecutorService {
	private final ExecutorService executorService;

	public WrappingExecutorService(ExecutorService executorService) {
		this.executorService = executorService;
	}

	protected abstract Runnable wrap(Runnable r);

	@Override
	public void execute(Runnable command) {
		executorService.execute(wrap(command));
	}

	@Override
	public void shutdown() {
		executorService.shutdown();
	}

	@Override
	public List<Runnable> shutdownNow() {
		return executorService.shutdownNow();
	}

	@Override
	public boolean isShutdown() {
		return executorService.isShutdown();
	}

	@Override
	public boolean isTerminated() {
		return executorService.isTerminated();
	}

	@Override
	public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
		return executorService.awaitTermination(timeout, unit);
	}
}
