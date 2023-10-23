package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.lang.reflect.Array;
import java.util.Optional;
import java.util.concurrent.BlockingDeque;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;

/**
 * Encryption and decryption may happen in parallel, but we still need to maintain the order of the packets.
 * This is what the pipeline looks like;  since the cryptography happens in parallel, the order of the packets
 * on the output side may not be the same as the order of the packets on the input side.
 * <pre>
 * 		/---[crypto worker 1]--\
 * 		/                         \
 * 		[input] ---- [crypto worker 0] - [output]
 * 		\                         /
 * 		\---[crypto worker 2]----/
 * </pre>
 *
 *
 * <p>
 * To fix this, we have a separate output queue for each worker.  When the input side enqueues a packet to be processed,
 * it tags the packet with a sequence number and records the worker that it's sending it to.  It puts this into
 * a shared FIFO buffer.  The output side will then dequeue the next item from the buffer, and wait up to a certain
 * timeout for the packet to appear in the output queue for the worker that the input side recorded.
 * </p>
 *
 * <pre>
 *                                                                             Worker 1
 *                                                                           ┌──────────┐
 * Input queue                                                               │          │                                 Output queue
 * ┌───────────┐      ┌───────────┐      ┌───────────┐                       │          │                                ┌───────────┐      ┌───────────┐      ┌───────────┐
 * │           │----->│           │----->│           │            ┌─────────►│  Packet  ├─────┐                          │           │----->│           │----->│           │
 * └───────────┘      └───────────┘      └─────┬─────┘            │          │    n     │     │                          └───────────┘      └───────────┘      └───────────┘
 *                                             │                  │          │          │     │                                ▲
 *                                             │                  │          │          │     │                                │
 *                                             │                  │          └──────────┘     │                                │
 *                                             │                  │                           │                                │
 *                                             │                  │                           │                                │
 *                                             │                  │            Worker 2       │                                │
 *                                             │                  │          ┌──────────┐     │    ┌─────────────────┐         │
 *                                       ┌─────┴───────┐          │          │          │     │    │                 │         │
 *                                       │             │          │          │          │     │    │                 │         │
 *                                       │Input thread ├──────────┼─────────►│  Packet  ├─────┼───►│  Output thread  ├─────────┘
 *                                       │             │          │          │  n + 1   │     │    │                 │
 *                                       └─────┬───────┘          │          │          │     │    │                 │
 *                                             │                  │          │          │     │    └─────────────────┘
 *                                             │                  │          └──────────┘     │              ▲
 *                                             │                  │                           │              │
 *                                             │                  │                           │              │
 *                                             │                  │            Worker 3       │              │
 *                                             │                  │          ┌──────────┐     │              │
 *                                             │                  │          │          │     │              │
 *                                             │                  │          │  Packet  │     │              │
 *                                             │                  └─────────►│  n + 3   ├─────┘              │
 *                                             │                             │          │                    │
 *                                             │                             │          │                    │
 *                                             │                             └──────────┘                    │
 *                                             │                                                             │
 *                                             │                  ┌────────────────┬┬───────────┐            │
 *                                             └────────────────► │  Packet n      ││ Worker 1  ├────────────┘
 *                                                                ├────────────────┼┼───────────┤
 *                                                                ├────────────────┼┼───────────┤
 *                                                                │  Packet n + 1  ││ Worker 2  │
 *                                                                ├────────────────┼┼───────────┤
 *                                                                ├────────────────┼┼───────────┤
 *                                                                │      ...       ││           │
 *                                                                └────────────────┴┴───────────┘
 * </pre>
 */

public class OrderedCryptographicExecutor<T, U> {
	private static final VarHandle WORKER_INDEX;

	static {
		try {
			WORKER_INDEX = MethodHandles.lookup().findVarHandle(OrderedCryptographicExecutor.class, "workerIndex", long.class);
		} catch (NoSuchFieldException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private final ReentrantLock enqueueLock = new ReentrantLock(false);
	private final ReentrantLock dequeueLock = new ReentrantLock(false);

	private final BlockingDeque<PacketReference> packetOrderFifo = new LinkedBlockingDeque<>();

	private final Worker[] workers;

	private final int workerCount;
	private volatile long workerIndex = 0; // round-robin

	public OrderedCryptographicExecutor(int workerCount, ExceptionMapper<T, U> mapper, BiConsumer<Exception, T> errorHandler) {
		this.workerCount = workerCount;
		this.workers = (Worker[]) Array.newInstance(Worker.class, workerCount);

		for (int i = 0; i < workerCount; i++) {
			workers[i] = new Worker(i, mapper, errorHandler);
		}
	}

	/**
	 * Adds an item to the queue to be processed by one of the workers.
	 *
	 * @param item the item to be processed
	 */
	public boolean enqueue(T item) {
		enqueueLock.lock();

		try {
			int assignedWorker = nextWorker();
			var packetReference = new PacketReference(item, assignedWorker);

			packetOrderFifo.add(packetReference);
			return workers[assignedWorker].submit(item);
		} finally {
			enqueueLock.unlock();
		}
	}

	/**
	 * Dequeues the next item from the queue, waiting for it to be processed by the worker.
	 *
	 * @return the processed item
	 * @throws InterruptedException if the thread is interrupted while waiting for the item to be processed
	 */
	public U dequeue() throws InterruptedException {
		U result;
		do {
			PacketReference nextReference;
			Worker worker;

			dequeueLock.lock();

			try {
				nextReference = packetOrderFifo.take();
				worker = workers[nextReference.workerIndex];
			} finally {
				dequeueLock.unlock();
			}

			result = worker.take();
		} while (result == null);
		return result;
	}

	private int nextWorker() {
		return (int) ((long) WORKER_INDEX.getAndAdd(this, 1L) % workerCount);
	}

	public void close() {
		for (var worker : workers) {
			worker.close();
		}
	}

	public interface ExceptionMapper<T, U> {
		U apply(T t) throws Exception;
	}

	record PacketReference(Object packet, int workerIndex) {
	}

	private class Worker implements Runnable {

		private final ExceptionMapper<T, U> mapper;
		private final BiConsumer<Exception, T> errorHandler;

		private final BlockingQueue<T> inputQueue = new LinkedBlockingQueue<>(1024);
		private final BlockingDeque<Optional<U>> outputQueue = new LinkedBlockingDeque<>(1024);

		private final Thread thread;

		public Worker(int index, ExceptionMapper<T, U> mapper, BiConsumer<Exception, T> errorHandler) {
			this.mapper = mapper;
			this.errorHandler = errorHandler;

			thread = new Thread(this, "Crypto worker " + index);
			if (!WireguardDevice.SYNCRONOUS_PIPELINE)
				thread.start();
		}

		public void run() {
			try {
				while (!Thread.interrupted()) {
					doItem(inputQueue.take());
				}
			} catch (Throwable ignored) {
				ignored.printStackTrace();
			}
		}

		private void doItem(T item) throws InterruptedException {
			U result = null;
			try {
				result = mapper.apply(item);
			} catch (Exception e) {
				errorHandler.accept(e, item);
			} finally {
				outputQueue.add(Optional.ofNullable(result));
			}
		}

		public boolean submit(T item) {
			try {
				if (WireguardDevice.SYNCRONOUS_PIPELINE) {
					doItem(item);
					return true;
				} else {
					return inputQueue.offer(item);
				}
			} catch (InterruptedException e) {
				throw new RuntimeException(e);
			}
		}

		public U take() throws InterruptedException {
			return outputQueue.take().orElse(null);
		}

		public void close() {
			thread.interrupt();
		}
	}
}
