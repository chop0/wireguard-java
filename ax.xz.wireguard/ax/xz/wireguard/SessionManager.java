package ax.xz.wireguard;

import ax.xz.wireguard.message.MessageInitiation;
import ax.xz.wireguard.message.MessageResponse;
import org.slf4j.Logger;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

class SessionManager implements Runnable {
	private static final Logger logger = ScopedLogger.getLogger(SessionManager.class);

	private final ReentrantLock sessionLock = new ReentrantLock();
	private final Condition sessionChangedCondition = sessionLock.newCondition();

	private final LinkedBlockingQueue<Map.Entry<MessageResponse, SocketAddress>> inboundHandshakeResponseQueue = new LinkedBlockingQueue<>();
	// A queue of inbound handshake initiation messages
	private final LinkedBlockingQueue<Map.Entry<MessageInitiation, SocketAddress>> inboundHandshakeInitiationQueue = new LinkedBlockingQueue<>();

	private final Peer peer;
	private final WireguardDevice device;

	// The current session.  Null iff no session is established and a handshake has not begun.
	private EstablishedSession session;

	private final SocketAddress endpoint;

	SessionManager(Peer peer, WireguardDevice device, SocketAddress endpoint) {
		this.peer = peer;
		this.device = device;
		this.endpoint = endpoint;
	}

	void receiveHandshakeResponse(SocketAddress address, MessageResponse message) {
		inboundHandshakeResponseQueue.add(Map.entry(message, address));
	}

	private void transmit(ByteBuffer data, SocketAddress remoteAddress) throws IOException {
		if (remoteAddress == null)
			throw new IllegalStateException("Remote address not set");

		device.transmit(remoteAddress, data);
	}

	private void recordIOException(IOException e) {
		logger.warn("Detected broken connection to {}", peer.getAuthority());

		if (endpoint != null) {
			logger.debug("Attempting to recover connection using endpoint");
			setSession(null);
			sessionChangedCondition.signalAll();
		}

		throw new RuntimeException(e); // TODO:  recover
	}

	/**
	 * Returns the current session, or null if no session is established.
	 */
	public EstablishedSession tryGetSessionNow() {
		return session;
	}

	/**
	 * Waits for a session to be established, or returns null if the timeout expires.
	 */
	public EstablishedSession waitForSession() throws InterruptedException {
		sessionLock.lockInterruptibly();
		try {
			while (isSessionDead()) {
				sessionChangedCondition.await();
			}

			return session;
		} finally {
			sessionLock.unlock();
		}
	}

	public void run() {
		try (var executor = new WorkerThreadScope()) {
			executor.fork(this::sessionInitiationThread);
			executor.fork(this::handshakeResponderThread);

			executor.join();
		} catch (InterruptedException e) {
			logger.debug("Broken connection worker interrupted");
		} catch (Throwable e) {
			logger.warn("Unhandled error in broken connection worker", e);
			throw e;
		} finally {
			logger.debug("Broken connection worker shutting down");
		}
	}

	private void sessionInitiationThread() {
		sessionLock.lock();

		try {
			while (!Thread.interrupted()) {
				if (isSessionDead()) {
					if (hasEndpoint()) {
						try {
							setSession(performInitiatorHandshake());
						} catch (Throwable bpe) {
							logger.warn("Failed to complete handshake", bpe);
						}
					} else {
						logger.warn("No endpoint set;  waiting for remote handshake initiation");
					}
				}

				var timeTillExpiration = session == null ? Duration.ofDays(365) : Duration.between(Instant.now(), session.expiration());
				//noinspection ResultOfMethodCallIgnored
				sessionChangedCondition.await(timeTillExpiration.toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.debug("Session initiation thread interrupted");
		} finally {
			sessionLock.unlock();
		}
	}

	private boolean isSessionDead() {
		var session = this.session;
		return session == null || session.isExpired();
	}

	private static final AtomicInteger nextSessionIndex = new AtomicInteger(1);

	private void handshakeResponderThread() {
		try {
			while (!Thread.interrupted()) {
				var initiation = inboundHandshakeInitiationQueue.take();
				logger.info("Received handshake initiation from {}", initiation.getValue());

				sessionLock.lock();
				try {
					var message = initiation.getKey();
					var address = initiation.getValue();

					var handshake = Handshakes.responderHandshake(device.getStaticIdentity(), message.ephemeral(), message.encryptedStatic(), message.encryptedTimestamp());

					int localIndex = nextSessionIndex.getAndIncrement();
					var packet = MessageResponse.create(localIndex, initiation.getKey().sender(), handshake.getLocalEphemeral(), handshake.getEncryptedEmpty(), handshake.getRemotePublicKey());
					transmit(packet.buffer(), address);

					setSession(new EstablishedSession(device, handshake.getKeypair(), address, localIndex, message.sender()));
					logger.info("Completed handshake with {} (responder)", peer.getAuthority());
				} catch (BadPaddingException e) {
					continue;
				} catch (IOException e) {
					recordIOException(e);
				} finally {
					sessionLock.unlock();
				}
			}
		} catch (InterruptedException e) {
			logger.debug("Handshake responder thread interrupted");
		}
	}

	/**
	 * Sets the session. Requires that the sessionLock be held.
	 */
	private void setSession(EstablishedSession session) {
		if (!sessionLock.isHeldByCurrentThread())
			throw new IllegalStateException("Session lock not held");

		if (session == null) {
			this.session = null;
			return;
		}

		if (this.session != null)
			device.clearSessionIndex(this.session.localIndex());

		this.session = session;
		device.setPeerSessionIndex(peer, session.localIndex());

		sessionChangedCondition.signalAll();
	}

	private EstablishedSession performInitiatorHandshake() throws IOException, BadPaddingException, InterruptedException {
		while (true) {
			logger.info("Initiating handshake");

			var handshake = Handshakes.initiateHandshake(device.getStaticIdentity(), peer.getRemoteStatic(), peer.getPresharedKey());

			int localIndex = nextSessionIndex.getAndIncrement();
			device.setPeerSessionIndex(peer, localIndex);

			var packet = MessageInitiation.create(localIndex, handshake.getLocalEphemeral().publicKey(), handshake.getEncryptedStatic(), handshake.getEncryptedTimestamp());
			transmit(packet.getSignedBuffer(peer.getRemoteStatic()), endpoint);

			var response = inboundHandshakeResponseQueue.poll(5, TimeUnit.SECONDS);
			if (response == null) {
				logger.warn("Timed out waiting for handshake response");
				continue;
			}

			var message = response.getKey();

			var kp = handshake.consumeMessageResponse(message.ephemeral(), message.encryptedEmpty());
			return new EstablishedSession(device, kp, endpoint, localIndex, message.sender());
		}
	}

	public void receiveInitiation(SocketAddress address, MessageInitiation messageInitiationInboundMessage) {
		inboundHandshakeInitiationQueue.add(Map.entry(messageInitiationInboundMessage, address));
	}

	/**
	 * Returns true if we can initiate a handshake.
	 *
	 * @return true if this peer has an endpoint set
	 */
	public boolean hasEndpoint() {
		return endpoint != null;
	}

	public SocketAddress getEndpoint() {
		return endpoint;
	}
}
