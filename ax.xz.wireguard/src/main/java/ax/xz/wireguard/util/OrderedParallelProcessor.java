package ax.xz.wireguard.util;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.concurrent.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class OrderedParallelProcessor {
	private static final VarHandle TAIL;

	static {
		try {
			TAIL = MethodHandles.lookup().findVarHandle(OrderedParallelProcessor.class, "tail", Guard.class);
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private final Lock lock = new ReentrantLock(false);
	private volatile Guard tail;

	/**
	 * Stores this thread's order relative to other threads calling register()
	 */
	public Guard register() {
		Guard newGuard = new Guard();

		while (true) {
			Guard currentTail = (Guard) TAIL.getVolatile(this);
			if (currentTail != null)
				newGuard.next = currentTail;

			if (TAIL.compareAndSet(this, currentTail, newGuard)) {
				return newGuard;
			}
		}
	}

	/**
	 * Marks this thread's task as complete and blocks until all threads that called register() before this thread complete their tasks.
	 * Must be called from the same thread that called register().
	 *
	 * Calls the task in the order of the threads that called register().
	 */
	public void markCompleteAndRunOrdered(Guard current, Runnable task) throws InterruptedException {
		lock.lock();

		try {
			if (current.isComplete)
				throw new IllegalStateException("Task already completed");

			if (current.next != null) {
				while (!current.next.isComplete) {
					current.next.condition.await();
				}
			}

			task.run();
			current.isComplete = true;
			current.condition.signalAll();
		} finally {
			lock.unlock();
		}
	}

	public class Guard implements AutoCloseable {
		private final Condition condition = lock.newCondition();
		private Guard next;
		private boolean isComplete = false;

		@Override
		public void close() {
			lock.lock();
			try {
				if (!isComplete) {
					isComplete = true;
					condition.signalAll();
				}
			} finally {
				lock.unlock();
			}
		}
	}

	public static void main(String... argv) throws BrokenBarrierException, InterruptedException {
		OrderedParallelProcessor processor = new OrderedParallelProcessor();

		var result = new ConcurrentLinkedQueue<Integer>();

		try (var sts = Executors.newVirtualThreadPerTaskExecutor()) {
			for (int i = 0; i < 1000; i++) {
				var barrier = new CyclicBarrier(2);
				int finalI = i;
				Runnable task = () -> {
					try (var guard = processor.register()) {
						System.out.println(finalI + " is processing");

						barrier.await();
						Thread.sleep((long) (Math.random() * 1000));

						System.out.println(finalI + " finished processing");
						processor.markCompleteAndRunOrdered(guard, () -> result.add(finalI));
					} catch (InterruptedException | BrokenBarrierException e) {
						throw new RuntimeException(e);
					}
				};

				sts.submit(task);
				barrier.await();
			}

			sts.shutdown();
			sts.awaitTermination(999_999_999, TimeUnit.DAYS);
		}

		// verify that the result is ordered
		int last = 0;
		for (int i : result) {
			if (i != last++) {
				throw new IllegalStateException("Result is not ordered");
			}
		}
	}
}

