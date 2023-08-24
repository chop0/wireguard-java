package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.PersistentTaskExecutor;
import ax.xz.wireguard.device.WireguardDevice;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger.Level.*;

/**
 * A skeleton of a SessionManager that handles the session state and concurrency.
 */
abstract sealed class SessionManagerBase permits SessionManager {
	private static final System.Logger logger = System.getLogger(SessionManagerBase.class.getName());

	// The lock behind which all peer state is stored
	protected final ReentrantLock lock = new ReentrantLock();

	// The condition that is signalled when the peer state is modified
	protected final Condition condition = lock.newCondition();

	private final WireguardDevice device;
	private final Peer.PeerConnectionInfo connectionInfo;

	protected SessionManagerBase(WireguardDevice device, Peer.PeerConnectionInfo connectionInfo) {
		this.connectionInfo = connectionInfo;
		this.device = device;
	}

	public void run() {
		try (var executor = new PersistentTaskExecutor<>("Session workers", IOException::new, logger)) {
			executor.submit("Session initiation thread", this::sessionInitiationThread);
			executor.submit("Handshake responder thread", this::handshakeResponderThread);
			executor.submit("Keepalive thread", this::keepaliveThread);
			executor.submit("Transport decryption thread", this::transportDecryptionThread);

			executor.join();
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Broken connection worker interrupted");
		} catch (Throwable e) {
			logger.log(WARNING, "Unhandled error in broken connection worker", e);
			throw e;
		} finally {
			logger.log(DEBUG, "Broken connection worker shutting down");

			if (lock.tryLock()) {
				try {
					cleanup();
				} finally {
					lock.unlock();
				}
			} else {
				logger.log(ERROR, "Failed to acquire lock, even though all workers should be shut down.  This is a bug.");
			}
		}
	}

	private void transportDecryptionThread() {
		try {
			while (!Thread.interrupted()) {
				processTransportMessages();
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Decryption worker interrupted");
		} finally {
			logger.log(DEBUG, "Decryption worker shutting down");
		}
	}


	private void sessionInitiationThread() {
		lock.lock();

		try {
			while (!Thread.interrupted()) {
				attemptSessionRecoveryIfRequired();
				condition.await(Duration.between(Instant.now(), currentSessionExpiration()).toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Session initiation thread interrupted");
		} finally {
			lock.unlock();
		}
	}

	private void keepaliveThread() {
		lock.lock(); // condition-based wait requires the lock to be held
		try {
			while (!Thread.interrupted()) {
				sendKeepaliveIfNeeded();
				condition.await(keepaliveInterval().toMillis(), TimeUnit.MILLISECONDS);
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

	private void handshakeResponderThread() {
		try {
			while (!Thread.interrupted()) {
				processHandshakeInitiationMessage();
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Handshake responder interrupted");
		} finally {
			logger.log(DEBUG, "Handshake responder shutting down");
		}
	}

	protected abstract Instant currentSessionExpiration();

	protected abstract Duration keepaliveInterval();

	/**
	 * Waits till a handshake initiation message has arrived, and then processes it.
	 */
	protected abstract void processHandshakeInitiationMessage() throws InterruptedException;

	/**
	 * Waits till at least one transport message has arrived, and then processes them.
	 */
	protected abstract void processTransportMessages() throws InterruptedException;

	/**
	 * Attempts to recover the session by initiating a connection, if
	 * necessary.
	 *
	 * @throws InterruptedException if the thread is interrupted whilst performing the handshake
	 */
	protected abstract void attemptSessionRecoveryIfRequired() throws InterruptedException;

	/**
	 * Sends a keepalive packet if needed.
	 * peerLock will be held when this method is called.
	 */
	protected abstract void sendKeepaliveIfNeeded();

	protected void cleanup() {
	}
}
