package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.Pool;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.OutgoingPeerPacket;
import ax.xz.wireguard.device.message.initiation.IncomingInitiation;
import ax.xz.wireguard.device.message.initiation.OutgoingInitiation;
import ax.xz.wireguard.device.message.response.IncomingResponse;
import ax.xz.wireguard.device.message.response.OutgoingResponse;
import ax.xz.wireguard.noise.handshake.Handshakes;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.util.PersistentTaskExecutor;

import javax.annotation.Nullable;
import javax.annotation.WillClose;
import javax.annotation.concurrent.GuardedBy;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
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

	private final DatagramChannel channel;


	// A queue of inbound handshake response messages [other peer -> this peer]
	private final BlockingQueue<IncomingResponse> inboundHandshakeResponseQueue = new LinkedBlockingQueue<>();

	// A queue of inbound handshake initiation messages [other peer -> this peer]
	private final BlockingQueue<IncomingInitiation> inboundHandshakeInitiationQueue = new LinkedBlockingQueue<>();

	// The keys and addresses used to connect to the peer
	private final Peer.PeerConnectionInfo connectionInfo;
	private final NoisePrivateKey localIdentity;

	// The device through which we communicate with the peer
	private final WireguardDevice device;
	private final Pool pool;
	// The current session.  Null iff no session is established and a handshake has not begun. This is private by peerLock.
	private EstablishedSession session;

	SessionManager(WireguardDevice device, DatagramChannel bidirectionalChannel, Peer.PeerConnectionInfo connectionInfo, NoisePrivateKey localIdentity, Pool pool) {
		this.connectionInfo = connectionInfo;
		this.channel = bidirectionalChannel;
		this.device = device;
		this.localIdentity = localIdentity;
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
				if (!isSessionAlive() && canInitiateHandshake()) for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++) {
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
				try (var initiation = inboundHandshakeInitiationQueue.take()) {
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
		try {
			channel.close();
		} catch (IOException e) {
			logger.log(WARNING, "Failed to close channel", e);
		}

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
	 * Returns true if we can initiate a handshake, false otherwise
	 */
	private boolean canInitiateHandshake() {
		return connectionInfo.endpoint() != null;
	}

	/**
	 * Attempts to initiate a handshake with the peer.  Returns true if the handshake was successful, false otherwise.
	 *
	 * @return true if the handshake was successful, false otherwise
	 */
	@GuardedBy("lock")
	private boolean attemptInitiatorHandshake() {
		try {
			var handshake = Handshakes.initiateHandshake(localIdentity, connectionInfo.remoteStatic(), connectionInfo.presharedKey());

			int localIndex = allocateNewSessionIndex();
			var packet = new OutgoingInitiation(
				pool.acquire(),
				localIndex,

				handshake.getLocalEphemeral().publicKey(),
				handshake.getEncryptedStatic(),
				handshake.getEncryptedTimestamp(),

				connectionInfo.remoteStatic()
			);

			transmit(packet, connectionInfo.endpoint());

			var response = inboundHandshakeResponseQueue.poll(5, TimeUnit.SECONDS);
			if (response == null) {
				logger.log(WARNING, "Handshake response timed out");
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
			var handshake = Handshakes.responderHandshake(localIdentity, initiation.ephemeral(), initiation.encryptedStatic(), initiation.encryptedTimestamp());

			int localIndex = allocateNewSessionIndex();
			var packet = new OutgoingResponse(
				pool.acquire(),
				initiation.originAddress(),

				localIndex,
				initiation.senderIndex(),

				handshake.getLocalEphemeral(),
				handshake.getEncryptedEmpty(),
				handshake.getRemotePublicKey()
			);

			transmit(packet, initiation.originAddress());

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
	 * Allocates a new session index and tells the device to route packets with that index to this peer.
	 */
	private int allocateNewSessionIndex() {
		return device.allocateNewSessionIndex(connectionInfo.remoteStatic());
	}

	/**
	 * Transmits the given packet to the given address and returns its backing buffer to the pool.
	 * This method does not route transport data (inc. keepalives), and only should be used for session control packets.
	 */
	private void transmit(@WillClose OutgoingPeerPacket packet, InetSocketAddress destination) throws IOException {
		try (packet) {
			channel.send(packet.transmissiblePacket().asByteBuffer(), destination);
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

	/**
	 * Handles an incoming initiation message from the peer.
	 *
	 * @param message the message to handle
	 */
	void handleInitiation(IncomingInitiation message) {
		inboundHandshakeInitiationQueue.offer(message);
	}

	/**
	 * Handles an incoming response message from the peer.
	 *
	 * @param message the message to handle
	 */
	void handleResponse(IncomingResponse message) {
		inboundHandshakeResponseQueue.offer(message);
	}

	/**
	 * Returns the current session, or null if no session is established.
	 */
	@Nullable
	EstablishedSession tryGetSessionNow() {
		return session;
	}
}
