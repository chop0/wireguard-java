package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.util.PersistentTaskExecutor;
import ax.xz.wireguard.util.RelinquishingQueue;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

final class SessionManager {
	private static final int HANDSHAKE_ATTEMPTS = 5;

	private Logger logger;

	private final Peer peer;

	// The lock behind which all peer state is stored
	private final ReentrantLock lock = new ReentrantLock();
	// The condition that is signalled when the peer state is modified
	private final Condition sessionCondition = lock.newCondition();

	// A queue of inbound handshake response messages
	private final RelinquishingQueue<MessageResponse> inboundHandshakeResponseQueue = new RelinquishingQueue<>(lock);

	// A queue of inbound handshake initiation messages
	private final RelinquishingQueue<Map.Entry<MessageInitiation, InetSocketAddress>> inboundHandshakeInitiationQueue = new RelinquishingQueue<>(lock);

	// The keys and addresses used to connect to the peer
	private final Peer.PeerConnectionInfo connectionInfo;

	// The device through which we communicate with the peer
	private final WireguardDevice device;

	// The current session.  Null iff no session is established and a handshake has not begun. This is private by peerLock.
	private EstablishedSession session;

	SessionManager(Peer peer, WireguardDevice device, Peer.PeerConnectionInfo connectionInfo) {
		this.peer = peer;
		this.connectionInfo = connectionInfo;
		this.device = device;
	}

	public void run() {
		logger = System.getLogger("[%s] %s".formatted(peer, SessionManager.class.getSimpleName()));

		try (var executor = new PersistentTaskExecutor<>(IOException::new, logger, Thread.ofVirtual().factory())) {
			executor.submit("Session initiation thread", this::sessionInitiationThread);
			executor.submit("Handshake responder thread", this::handshakeResponderThread);
			executor.submit("Keepalive thread", this::keepaliveThread);

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
				attemptSessionRecoveryIfRequired();
				if (session == null)
					sessionCondition.await();
				else
					sessionCondition.await(Duration.between(Instant.now(), session.expiration()).toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Session initiation thread interrupted");
			Thread.currentThread().interrupt();
		} finally {
			lock.unlock();
		}
	}

	private void keepaliveThread() {
		lock.lock();

		try {
			while (!Thread.interrupted()) {
				sendKeepaliveIfNeeded();

				if (session == null)
					sessionCondition.await();
				else
					sessionCondition.await(session.keepaliveInterval().toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Keepalive worker interrupted");
			Thread.currentThread().interrupt();
		} catch (Exception e) {
			logger.log(ERROR, "Keepalive worker failed", e);
		} finally {
			lock.unlock();
			logger.log(DEBUG, "Keepalive worker shutting down");
		}
	}

	private void handshakeResponderThread() {
		lock.lock();

		try {
			while (!Thread.interrupted()) {
				handleNextInitiation();
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Handshake responder interrupted");
			Thread.currentThread().interrupt();
		} finally {
			lock.unlock();
			logger.log(DEBUG, "Handshake responder shutting down");
		}
	}

	@GuardedBy("lock")
	private void handleNextInitiation() throws InterruptedException {
		var message = inboundHandshakeInitiationQueue.take();

		try {
			var initiation = message.getKey();
			var origin = message.getValue();

			setSession(HandshakeResponder.respond(device, initiation, connectionInfo.keepaliveInterval(), origin, device.allocateNewSessionIndex(peer)));
			logger.log(INFO, "Completed handshake (responder)");
		} catch (IOException e) {
			logger.log(WARNING, "Failed to complete handshake (responder)", e);
			killSession();
		} finally {
			message.getKey().close();
		}
	}

	@GuardedBy("lock")
	private void attemptSessionRecoveryIfRequired() throws InterruptedException {
		if (connectionInfo.endpoint() == null || !(session == null || session.isExpired())) {
			return;
		}

		for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++) {
			logger.log(INFO, "Initiating handshake with {0} (try {1} of {2})", connectionInfo, i + 1, HANDSHAKE_ATTEMPTS);

			try {
				var initiator = HandshakeInitiator.initiate(device, connectionInfo, device.allocateNewSessionIndex(peer));

				MessageResponse response;
				try {
					response = inboundHandshakeResponseQueue.poll(Duration.ofSeconds(5));
				} catch (TimeoutException ex) {
					logger.log(WARNING, "Handshake response timed out");
					continue;
				}

				try {
					initiator.consumeResponse(response);
					setSession(initiator.getSession());
				} finally {
					response.close();
				}

				logger.log(INFO, "Completed handshake (initiator)");
				break;
			} catch (IOException e) {
				logger.log(WARNING, "Handshake failed", e);
			}
		}
	}

	@GuardedBy("lock")
	private void sendKeepaliveIfNeeded() throws InterruptedException, IOException {
		if (session != null && session.needsKeepalive()) {
			session.sendKeepalive(device);
			logger.log(DEBUG, "Sent keepalive");
		}
	}

	/**
	 * Enqueues an inbound handshake response message to be processed.
	 * Eventually releases the buffer backing `message` when done with it
	 *
	 * @param message the message to enqueue
	 */
	void receiveHandshakeResponse(MessageResponse message) {
		lock.lock();

		try {
			inboundHandshakeResponseQueue.offer(message);
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Enqueues an inbound handshake initiation message to be processed.
	 * Releases the transport buffer when done with it
	 *
	 * @param address                         the address the message was received from
	 * @param messageInitiationInboundMessage the message to enqueue
	 */
	void receiveInitiation(InetSocketAddress address, MessageInitiation messageInitiationInboundMessage) {
		lock.lock();

		try {
			inboundHandshakeInitiationQueue.offer(Map.entry(messageInitiationInboundMessage, address));
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Sets the session. Requires that the peerLock be held.
	 */
	@GuardedBy("lock")
	private void setSession(@Nullable EstablishedSession session) {
		this.session = session;
		sessionCondition.signalAll();
	}


	/**
	 * Returns the current session, or null if no session is established.
	 */
	@Nullable
	EstablishedSession tryGetSessionNow() {
		return session;
	}

	/**
	 * Marks the session as dead.  Requires that the peerLock be held.
	 */
	@GuardedBy("lock")
	private void killSession() {
		setSession(null);
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
}
