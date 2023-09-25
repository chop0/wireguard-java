package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.PeerPacketRouter;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.initiation.OutgoingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.response.OutgoingResponse;
import ax.xz.wireguard.noise.handshake.Handshakes;
import ax.xz.wireguard.util.PersistentTaskExecutor;
import ax.xz.wireguard.util.Pool;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

final class SessionManager implements Runnable {
	private static final Duration DEFAULT_KEEPALIVE_INTERVAL = Duration.ofSeconds(25);
	private static final int HANDSHAKE_ATTEMPTS = 5;

	private static final Logger logger = System.getLogger(SessionManager.class.getName());

	/**
	 * The lock protecting all the session state
	 */
	final ReentrantLock lock = new ReentrantLock();

	/**
	 * The condition that is signalled when the peer state is modified
	 */
	final Condition condition = lock.newCondition();

	// The keys and addresses used to connect to the peer
	private final PeerConnectionInfo connectionInfo;

	// The device through which we communicate with the peer
	private final PeerPacketRouter.PeerPacketChannel channel;
	private final Pool pool;

	// The current session.  Null iff no session is established and a handshake has not begun. This is private by peerLock.
	private EstablishedSession session;

	SessionManager(Pool pool, PeerPacketRouter.PeerPacketChannel bindChannel, PeerConnectionInfo connectionInfo) {
		this.connectionInfo = connectionInfo;
		this.channel = bindChannel;
		this.pool = pool;
	}

	public void run() {
		try (var executor = new PersistentTaskExecutor<>(IOException::new, logger, Thread.ofVirtual().factory())) {
			executor.submit("Session initiation thread", this::sessionInitiationThread);
			executor.submit("Handshake responder thread", this::handshakeResponderThread);

			executor.awaitTermination();
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Broken connection worker interrupted");
			Thread.currentThread().interrupt();
		} catch (Exception e) {
			logger.log(WARNING, "Unhandled error in broken connection worker", e);
			throw e;
		} finally {
			logger.log(DEBUG, "Broken connection worker;  shutting down");
			cleanup();
		}
	}

	private void sessionInitiationThread() {
		lock.lock();

		try {
			while (!Thread.interrupted()) {
				if (!isSessionAlive() && connectionInfo.canInitiateHandshake()) for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++) {
					logger.log(INFO, "Initiating handshake with {0} (try {1} of {2})", connectionInfo, i + 1, HANDSHAKE_ATTEMPTS);

					if (attemptInitiatorHandshake()) break;
				}

				condition.await();
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Session initiation thread interrupted");
			Thread.currentThread().interrupt();
		} finally {
			lock.unlock();
		}
	}

	private void handshakeResponderThread() {
		lock.lock();

		try {
			while (!Thread.interrupted()) {
				try (var initiation = channel.takeInitiation()) {
					performHandshakeResponse(initiation);
				}
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Handshake responder interrupted");
			Thread.currentThread().interrupt();
		} finally {
			lock.unlock();
			logger.log(DEBUG, "Handshake responder shutting down");
		}
	}

	private void cleanup() {
		if (lock.tryLock()) {
			try {
				killSession();
			} finally {
				lock.unlock();
			}
		} else {
			logger.log(ERROR, "Failed to acquire lock, even though all workers should be shut down.  This is a bug.");
		}
	}

	/**
	 * Returns true if the session is alive, false otherwise
	 */
	private boolean isSessionAlive() {
		var session = this.session;
		return session != null && !session.isExpired();
	}


	/**
	 * Attempts to initiate a handshake with the peer.  Returns true if the handshake was successful, false otherwise.
	 *
	 * @return true if the handshake was successful, false otherwise
	 */
	@GuardedBy("lock")
	private boolean attemptInitiatorHandshake() {
		try {
			var handshake = Handshakes.initiateHandshake(connectionInfo.handshakeDetails());

			int localIndex = channel.prepareNewSession(connectionInfo.endpoint());
			var packet = new OutgoingInitiation(
				pool.acquire(),
				localIndex,

				handshake.getLocalEphemeral().publicKey(),
				handshake.getEncryptedStatic(),
				handshake.getEncryptedTimestamp(),

				connectionInfo.handshakeDetails().remoteKey()
			);

			try (packet) {
				channel.send(packet);
			}

			IncomingResponse response;
			try (var sts = new StructuredTaskScope.ShutdownOnSuccess<IncomingResponse>()) {
				sts.fork(channel::takeResponse);
				sts.joinUntil(Instant.now().plusSeconds(5));

				response = sts.result();
			} catch (TimeoutException e) {
				logger.log(WARNING, "Handshake response timed out");
				return false;
			} catch (ExecutionException e) {
				if (e.getCause() instanceof InterruptedException)
					Thread.currentThread().interrupt();
				else
					logger.log(WARNING, "Failed to take handshake response", e);

				return false;
			}

			try (response) {
				var kp = handshake.consumeMessageResponse(response.ephemeral(), response.encryptedNothing());
				setSession(new EstablishedSession(kp, connectionInfo.endpoint(), response.receiverIndex(), connectionInfo.keepaliveInterval()));
			} catch (BadPaddingException ex) {
				throw new IOException("Failed to decrypt response", ex);
			}

			logger.log(INFO, "Completed handshake (initiator)");
			return true;
		} catch (IOException | InterruptedException e) {
			logger.log(WARNING, "Handshake failed", e);
			return false;
		}
	}

	@GuardedBy("lock")
	private void performHandshakeResponse(IncomingInitiation initiation) throws InterruptedException {
		try {
			var handshake = Handshakes.responderHandshake(connectionInfo.handshakeDetails(), initiation.ephemeral(), initiation.encryptedStatic(), initiation.encryptedTimestamp());

			int localIndex = channel.prepareNewSession(initiation.originAddress());
			var packet = new OutgoingResponse(
				pool.acquire(),
				initiation.originAddress(),

				localIndex,
				initiation.senderIndex(),

				handshake.getLocalEphemeral(),
				handshake.getEncryptedEmpty(),
				handshake.getRemotePublicKey()
			);

			try (packet) {
				channel.send(packet);
			}

			setSession(new EstablishedSession(handshake.getKeypair(), initiation.originAddress(), initiation.senderIndex(), DEFAULT_KEEPALIVE_INTERVAL));
			logger.log(INFO, "Completed handshake (responder)");
		} catch (IOException e) {
			logger.log(WARNING, "Failed to complete handshake (responder)", e);
		} catch (BadPaddingException e) {
			logger.log(WARNING, "Failed to decrypt handshake initiation", e);
		}
	}

	/**
	 * Marks the session as dead.  Requires that the peerLock be held.
	 */
	@GuardedBy("lock")
	private void killSession() {
		setSession(null);
	}

	/**
	 * Sets the session. Requires that the peerLock be held.
	 */
	@GuardedBy("lock")
	private void setSession(@Nullable EstablishedSession session) {
		this.session = session;
		condition.signalAll();
	}

	/**
	 * Returns the current session, or null if no session is established.
	 */
	@Nullable
	EstablishedSession tryGetSessionNow() {
		return session;
	}
}
