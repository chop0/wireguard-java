package ax.xz.wireguard.util;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedList;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

/**
 * A linked list that waits on a condition derived from
 * a given lock.
 */
public class RelinquishingQueue<T> {
	private final LinkedList<T> queue = new LinkedList<>();

	private final Condition condition;

	public RelinquishingQueue(Lock lock) {
		this.condition = lock.newCondition();
	}

	/**
	 * Adds a new element to the queue and signals the condition.
	 * The caller must hold the lock.
	 *
	 * @param element the element to add
	 */
	public void offer(T element) {
		queue.add(element);
		condition.signal();
	}

	/**
	 * Removes and returns the first element in the queue.
	 * If the queue is empty, the caller will wait on the condition.
	 * The caller must hold the lock.
	 *
	 * @return the first element in the queue
	 * @throws InterruptedException if the thread is interrupted while waiting
	 */
	public T take() throws InterruptedException {
		while (true) {
			if (!queue.isEmpty())
				return queue.poll();
			condition.await();
		}
	}

	/**
	 * Removes and returns the first element in the queue.
	 * If the queue is empty, the caller will wait on the condition for the given duration.
	 * The caller must hold the lock.
	 *
	 * @param timeout the maximum time to wait
	 * @return the first element in the queue, or null if the timeout expires
	 * @throws InterruptedException if the thread is interrupted while waiting
	 */
	public T poll(Duration timeout) throws InterruptedException {
		var timeoutTime = Date.from(Instant.now().plus(timeout));
		for (;;) {
			if (!queue.isEmpty())
				return queue.poll();

			if (!condition.awaitUntil(timeoutTime))
				return null;
		}
	}
}
