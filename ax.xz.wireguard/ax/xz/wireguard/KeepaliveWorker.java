package ax.xz.wireguard;

import org.slf4j.Logger;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

class KeepaliveWorker implements Runnable {
	private static final Logger logger = ScopedLogger.getLogger(KeepaliveWorker.class);

	private final SessionManager sessionManager;

	private final Lock lock = new ReentrantLock();
	private final Condition keepaliveCondition = lock.newCondition();

	private final Duration keepaliveInterval;

	private Instant lastKeepalive;
	private boolean keepaliveRequested = false;

	KeepaliveWorker(SessionManager sessionManager, Duration keepaliveInterval) {
		this.sessionManager = sessionManager;
		this.keepaliveInterval = keepaliveInterval;
	}

	private boolean needsKeepalive() {
		return sessionManager.tryGetSessionNow() != null && (keepaliveRequested || lastKeepalive == null || lastKeepalive.plus(keepaliveInterval).isBefore(Instant.now()));
	}

	public void run() {
		lock.lock(); // this looks bad, but we spend most of our time waiting for the condition anyway
		try {
			while (!Thread.interrupted()) {
				if (needsKeepalive()) {
					try {
						sendKeepalive();
					} catch (IOException e) {
						logger.warn("Keepalive failed", e);
					}
				}

				keepaliveCondition.await(keepaliveInterval.toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.debug("Keepalive worker interrupted");
		} catch (Throwable e) {
			logger.error("Keepalive worker failed", e);
			throw e;
		} finally {
			lock.unlock();
			logger.debug("Keepalive worker shutting down");
		}
	}

	private void sendKeepalive() throws InterruptedException, IOException {
		var session = sessionManager.tryGetSessionNow();
		if (session == null) { // possible race
			logger.warn("Could not send keepalive (session dead?)");
			return;
		}

		session.writeTransportPacket(ByteBuffer.allocate(0));

		lastKeepalive = Instant.now();
		keepaliveRequested = false;

		logger.debug("Sent keepalive");
	}

	void requestKeepalive() {
		lock.lock();
		try {
			keepaliveRequested = true;
			keepaliveCondition.signalAll();
		} finally {
			lock.unlock();
		}
	}
}
