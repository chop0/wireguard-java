package ax.xz.wireguard.device.peer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

class KeepaliveWorker implements Runnable {
	private static final Logger logger = System.getLogger(KeepaliveWorker.class.getName());

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
						logger.log(WARNING, "Keepalive failed", e);
					}
				}

				//noinspection ResultOfMethodCallIgnored
				keepaliveCondition.await(keepaliveInterval.toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Keepalive worker interrupted");
		} catch (Throwable e) {
			logger.log(ERROR, "Keepalive worker failed", e);
			throw e;
		} finally {
			lock.unlock();
			logger.log(DEBUG, "Keepalive worker shutting down");
		}
	}

	private void sendKeepalive() throws IOException {
		var session = sessionManager.tryGetSessionNow();
		if (session == null) { // possible race
			logger.log(WARNING, "Could not send keepalive (session dead?)");
			return;
		}

		session.writeTransportPacket(ByteBuffer.allocate(0));

		lastKeepalive = Instant.now();
		keepaliveRequested = false;

		logger.log(DEBUG, "Sent keepalive");
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
