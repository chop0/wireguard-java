package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.initiation.OutgoingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.response.OutgoingResponse;
import ax.xz.wireguard.noise.handshake.Handshakes;
import ax.xz.wireguard.spi.PeerChannel;
import ax.xz.wireguard.spi.WireguardRouter;
import ax.xz.wireguard.util.PacketBufferPool;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;
import static java.util.Objects.requireNonNull;

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

	private final WireguardRouter router;

	private final PeerChannel transportChannel;
	private final SynchronousQueue<IncomingResponse> responseQueue = new SynchronousQueue<>();

	private final PacketBufferPool pool = PacketBufferPool.shared(4);

	// The current session.  Null iff no session is established and a handshake has not begun. This is private by peerLock.
	private EstablishedSession session;

	SessionManager(PeerConnectionInfo connectionInfo, WireguardRouter router, PeerChannel transportChannel) {
		this.connectionInfo = connectionInfo;
		this.router = router;

		this.transportChannel = transportChannel;
	}

	public void run() {
		lock.lock();

		try {
			while (!Thread.interrupted()) {
				if (!isSessionAlive() && connectionInfo.hasEndpoint())
					for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++) {
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
			var endpoint = requireNonNull(connectionInfo.endpoint());

			var handshake = Handshakes.initiateHandshake(connectionInfo.handshakeDetails());
			int localIndex = shuffleIndex();

			var packet = new OutgoingInitiation(
				pool.acquire(),
				localIndex,

				handshake.getLocalEphemeral().publicKey(),
				handshake.getEncryptedStatic(),
				handshake.getEncryptedTimestamp(),

				connectionInfo.handshakeDetails().remoteKey()
			);

			try (packet) {
				router.send(packet.transmissiblePacket().asByteBuffer(), endpoint);
			}

			IncomingResponse response;
			try (var sts = new StructuredTaskScope.ShutdownOnSuccess<IncomingResponse>()) {
				sts.fork(responseQueue::take);
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

				setSession(new EstablishedSession(kp, response.senderIndex(), connectionInfo.keepaliveInterval()));
				transportChannel.connect(response.originAddress());
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

	/**
	 * Sets the session. Requires that the peerLock be held.
	 */
	@GuardedBy("lock")
	private void setSession(@Nullable EstablishedSession session) {
		this.session = session;
		condition.signalAll();
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
	 * Marks the session as dead.  Requires that the peerLock be held.
	 */
	@GuardedBy("lock")
	private void killSession() {
		setSession(null);
	}

	public void handleInitiation(IncomingInitiation initiation) {
		lock.lock();

		try {
			if (isSessionAlive()) {
				logger.log(DEBUG, "Received handshake initiation from {0}, but we already have a session with them", connectionInfo);
				return;
			}

			performHandshakeResponse(initiation);
		} finally {
			lock.unlock();
		}
	}

	public void handleResponse(IncomingResponse response) {
		try {
			responseQueue.offer(response, 5, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	@GuardedBy("lock")
	private void performHandshakeResponse(IncomingInitiation initiation) {
		try {
			var handshake = Handshakes.responderHandshake(connectionInfo.handshakeDetails(), initiation.ephemeral(), initiation.encryptedStatic(), initiation.encryptedTimestamp());

			int localIndex = shuffleIndex();
			var packet = new OutgoingResponse(
				pool.acquire(),

				localIndex,
				initiation.senderIndex(),

				handshake.getLocalEphemeral(),
				handshake.getEncryptedEmpty(),
				handshake.getRemotePublicKey()
			);

			try (packet) {
				router.send(packet.transmissiblePacket().asByteBuffer(), initiation.originAddress());
			}

			setSession(new EstablishedSession(handshake.getKeypair(), initiation.senderIndex(), DEFAULT_KEEPALIVE_INTERVAL));
			transportChannel.connect(initiation.originAddress());

			logger.log(INFO, "Completed handshake (responder)");
		} catch (IOException e) {
			logger.log(WARNING, "Failed to complete handshake (responder)", e);
		} catch (BadPaddingException e) {
			logger.log(WARNING, "Failed to decrypt handshake initiation", e);
		}
	}

	/**
	 * Returns the current session, or null if no session is established.
	 */
	@Nullable
	EstablishedSession tryGetSessionNow() {
		return session;
	}

	private int shuffleIndex() {
		return router.shuffleIndex(connectionInfo.handshakeDetails().remoteKey());
	}
}
