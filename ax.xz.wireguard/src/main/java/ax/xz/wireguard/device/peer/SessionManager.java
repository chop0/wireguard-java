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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

final class SessionManager {
	private static final int HANDSHAKE_ATTEMPTS = 5;

	private static final Logger logger = System.getLogger(SessionManager.class.getName());
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


	SessionManager(WireguardDevice device, Peer.PeerConnectionInfo connectionInfo) {
		this.connectionInfo = connectionInfo;
		this.device = device;
	}

	public void run() {
		try (var executor = new PersistentTaskExecutor<>("Session workers", IOException::new, logger)) {
			executor.submit("Session initiation thread", this::sessionInitiationThread);
			executor.submit("Handshake responder thread", this::handshakeResponderThread);
			executor.submit("Keepalive thread", this::keepaliveThread);

			executor.join();
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Broken connection worker interrupted");
		} catch (Throwable e) {
			logger.log(WARNING, "Unhandled error in broken connection worker", e);
			throw e;
		} finally {
			logger.log(DEBUG, "Broken connection worker shutting down");
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
		} catch (Throwable e) {
			logger.log(ERROR, "Keepalive worker failed", e);
			throw e;
		} finally {
			lock.unlock();
			logger.log(DEBUG, "Keepalive worker shutting down");
		}
	}

	private void handshakeResponderThread() {
		lock.lock();

		try {
			while (!Thread.interrupted()) {
				try {
					var message = inboundHandshakeInitiationQueue.take();
					var initiation = message.getKey();
					var origin = message.getValue();

					setSession(HandshakeResponder.respond(device, initiation, connectionInfo.keepaliveInterval(), origin, getNewSessionIndex()));
					logger.log(INFO, "Completed handshake (responder)");
				} catch (IOException e) {
					logger.log(WARNING, "Failed to complete handshake (responder)", e);
					killSession();
				}
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Handshake responder interrupted");
		} finally {
			lock.unlock();
			logger.log(DEBUG, "Handshake responder shutting down");
		}
	}

	@GuardedBy("lock")
	private void attemptSessionRecoveryIfRequired() throws InterruptedException {
		if (!(session == null || session.isExpired())) {
			return;
		}

		if (connectionInfo.endpoint() == null) {
			logger.log(WARNING, "No endpoint set;  waiting for remote handshake initiation");
			return;
		}

		for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++) {
			logger.log(INFO, "Initiating handshake (try {0} of {1})", i + 1, HANDSHAKE_ATTEMPTS);

			try {
				var initiator = HandshakeInitiator.initiate(device, connectionInfo, getNewSessionIndex());

				MessageResponse response;
				try {
					response = inboundHandshakeResponseQueue.poll(Duration.ofSeconds(5));
				} catch (TimeoutException ex) {
					logger.log(WARNING, "Handshake response timed out");
					continue;
				}

				initiator.consumeResponse(response);
				setSession(initiator.getSession());

				logger.log(INFO, "Completed handshake (initiator)");
				break;
			} catch (IOException e) {
				logger.log(WARNING, "Handshake failed", e);
			}
		}
	}

	@GuardedBy("lock")
	private void sendKeepaliveIfNeeded() {
		if (session != null && session.needsKeepalive()) {
			try {
				session.sendKeepalive(device);
				logger.log(DEBUG, "Sent keepalive");
			} catch (IOException e) {
				logger.log(WARNING, "Keepalive failed", e);
			}
		}
	}

	/**
	 * Enqueues an inbound handshake response message to be processed
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
	 * Enqueues an inbound handshake initiation message to be processed
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
		if (this.session != null)
			device.clearSessionIndex(this.session.localIndex());

		this.session = session;

		if (session != null)
			device.setPeerSessionIndex(connectionInfo.remoteStatic(), session.localIndex());

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

	/**
	 * Allocates a new local session index and sets it in the device.
	 *
	 * @return the new local session index
	 */
	private int getNewSessionIndex() {
		class SessionIndex {
			private static final AtomicInteger nextSessionIndex = new AtomicInteger(0);
		}

		int localIndex = SessionIndex.nextSessionIndex.getAndIncrement();
		device.setPeerSessionIndex(connectionInfo.remoteStatic(), localIndex);
		return localIndex;
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
