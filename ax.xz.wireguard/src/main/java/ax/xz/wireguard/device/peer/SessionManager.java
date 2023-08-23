package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.PersistentTaskExecutor;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;
import ax.xz.wireguard.noise.handshake.Handshakes;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

class SessionManager implements Runnable {
	private static final int HANDSHAKE_ATTEMPTS = 5;

	private static final Logger logger = System.getLogger(SessionManager.class.getName());

	// A queue of inbound handshake response messages
	private final LinkedBlockingQueue<Map.Entry<MessageResponse, InetSocketAddress>> inboundHandshakeResponseQueue = new LinkedBlockingQueue<>();

	// A queue of inbound handshake initiation messages
	private final LinkedBlockingQueue<Map.Entry<MessageInitiation, InetSocketAddress>> inboundHandshakeInitiationQueue = new LinkedBlockingQueue<>();

	// a queue of inbound transport messages
	private final LinkedBlockingQueue<Peer.TransportWithSession> inboundTransportQueue = new LinkedBlockingQueue<>();

	// a queue of transport messages that have been decrypted
	private final LinkedBlockingQueue<ByteBuffer> decryptedTransportQueue = new LinkedBlockingQueue<>();

	// The keys and addresses used to connect to the peer
	private final Peer.PeerConnectionInfo connectionInfo;

	// The device through which we communicate with the peer
	private final WireguardDevice device;

	// The last time a keepalive was sent for the current session
	private Instant lastKeepalive;

	private final ReentrantLock peerLock = new ReentrantLock();
	private final Condition setSessionCondition = peerLock.newCondition();

	// The current session.  Null iff no session is established and a handshake has not begun.
	private EstablishedSession session;

	SessionManager(WireguardDevice device, Peer.PeerConnectionInfo connectionInfo) {
		this.connectionInfo = connectionInfo;
		this.device = device;
	}

	void receiveHandshakeResponse(InetSocketAddress address, MessageResponse message) {
		inboundHandshakeResponseQueue.add(Map.entry(message, address));
	}

	/**
	 * Returns the current session, or null if no session is established.
	 */
	public EstablishedSession tryGetSessionNow() {
		return session;
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

			if (peerLock.tryLock()) {
				try {
					setSession(null);
				} finally {
					peerLock.unlock();
				}
			} else {
				logger.log(ERROR, "Failed to acquire lock, even though all workers should be shut down.  This is a bug.");
			}
		}
	}

	private void sessionInitiationThread() {
		peerLock.lock();

		try {
			while (!Thread.interrupted()) {
				if (isSessionDead()) {
					if (connectionInfo.endpoint() != null) {
						try {
							for (int i = 0; i < HANDSHAKE_ATTEMPTS; i++) {
								logger.log(INFO, "Initiating handshake (try {0} of {1})", i + 1, HANDSHAKE_ATTEMPTS);

								var handshake = Handshakes.initiateHandshake(device.getStaticIdentity(), connectionInfo.remoteStatic(), connectionInfo.presharedKey());

								var localIndex = getNewSessionIndex();
								var packet = MessageInitiation.create(localIndex, handshake.getLocalEphemeral().publicKey(), handshake.getEncryptedStatic(), handshake.getEncryptedTimestamp());
								device.transmit(connectionInfo.endpoint(), packet.getSignedBuffer(connectionInfo.remoteStatic()));

								var response = inboundHandshakeResponseQueue.poll(5, TimeUnit.SECONDS);
								if (response == null) {
									logger.log(WARNING, "Timed out waiting for handshake response");
									continue;
								}

								var message = response.getKey();

								var kp = handshake.consumeMessageResponse(message.ephemeral(), message.encryptedEmpty());
								setSession(new EstablishedSession(device, kp, connectionInfo.endpoint(), localIndex, message.sender()));
								break;
							}

						} catch (Throwable bpe) {
							logger.log(WARNING, "Failed to complete handshake", bpe);
						}
					} else {
						logger.log(WARNING, "No endpoint set;  waiting for remote handshake initiation");
					}
				}

				var timeTillExpiration = session == null ? Duration.ofDays(365) : Duration.between(Instant.now(), session.expiration());
				//noinspection ResultOfMethodCallIgnored
				setSessionCondition.await(timeTillExpiration.toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Session initiation thread interrupted");
		} finally {
			peerLock.unlock();
		}
	}

	private boolean isSessionDead() {
		var session = this.session;
		return session == null || session.isExpired();
	}

	private void handshakeResponderThread() {
		try {
			while (!Thread.interrupted()) {
				var initiation = inboundHandshakeInitiationQueue.take();
				logger.log(INFO, "Received handshake initiation from {0}", initiation.getValue());

				peerLock.lock();
				try {
					var message = initiation.getKey();
					var address = initiation.getValue();

					var handshake = Handshakes.responderHandshake(device.getStaticIdentity(), message.ephemeral(), message.encryptedStatic(), message.encryptedTimestamp());

					int localIndex = getNewSessionIndex();
					var packet = MessageResponse.create(localIndex, initiation.getKey().sender(), handshake.getLocalEphemeral(), handshake.getEncryptedEmpty(), handshake.getRemotePublicKey());
					device.transmit(address, packet.buffer());

					setSession(new EstablishedSession(device, handshake.getKeypair(), address, localIndex, message.sender()));
					logger.log(INFO, "Completed handshake (responder)");
				} catch (BadPaddingException ignored) {
				} catch (IOException e) {
					logger.log(WARNING, "Detected broken connection");

					if (connectionInfo.endpoint() != null) {
						logger.log(DEBUG, "Attempting to recover connection using endpoint");

						setSession(null);
						setSessionCondition.signalAll();
					}

					throw new RuntimeException("Exception in session worker with no endpoint set (necessary for connection recovery)", e);
				} finally {
					peerLock.unlock();
				}
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Handshake responder thread interrupted");
		}
	}

	private void keepaliveThread() {
		peerLock.lock();
		try {
			while (!Thread.interrupted()) {
				if (session != null &&
					(lastKeepalive == null || lastKeepalive.plus(connectionInfo.keepaliveInterval()).isBefore(Instant.now()))) {
					try {
						session.writeTransportPacket(ByteBuffer.allocate(0));
						lastKeepalive = Instant.now();

						logger.log(DEBUG, "Sent keepalive");
					} catch (IOException e) {
						logger.log(WARNING, "Keepalive failed", e);
					}
				}

				//noinspection ResultOfMethodCallIgnored
				setSessionCondition.await(connectionInfo.keepaliveInterval().toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Keepalive worker interrupted");
		} catch (Throwable e) {
			logger.log(ERROR, "Keepalive worker failed", e);
			throw e;
		} finally {
			peerLock.unlock();
			logger.log(DEBUG, "Keepalive worker shutting down");
		}
	}

	private void transportDecryptionThread() {
		try {
			while (!Thread.interrupted()) {
				processMessages(awaitInboundMessages());
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Decryption worker interrupted");
		} finally {
			logger.log(DEBUG, "Decryption worker shutting down");
		}
	}

	void receiveTransport(MessageTransport transport) {
		// no use waiting for a session, since if the session is not established, we will not be able to decrypt the message
		// because any sessions created in the future will have a different keypair
		var currentSession = session;
		if (currentSession == null)
			return;

		inboundTransportQueue.add(new Peer.TransportWithSession(transport, currentSession));
	}

	/**
	 * Removes a decrypted transport message from the queue, and waits if none is present
	 *
	 * @return decrypted transport packet received
	 * @throws InterruptedException if the thread is interrupted whilst waiting
	 */
	ByteBuffer receiveDecryptedTransport() throws InterruptedException {
		return decryptedTransportQueue.take();
	}

	/**
	 * Waits till at least one transport message is present in the queue.  When a message is present, drains the queue and returns a list
	 * of its prior contents.
	 *
	 * @return A list containing all messages received since the last call
	 * @throws InterruptedException if the thread is interrupted whilst waiting
	 */
	private ArrayList<Peer.TransportWithSession> awaitInboundMessages() throws InterruptedException {
		var messages = new ArrayList<Peer.TransportWithSession>(inboundTransportQueue.size());
		messages.add(inboundTransportQueue.take());
		inboundTransportQueue.drainTo(messages);
		return messages;
	}

	/**
	 * Decrypts all transport messages in the given list and puts them in the appropriate queue
	 *
	 * @param messages the messages to decrypt
	 * @throws InterruptedException if the thread is interrupted whilst waiting
	 */
	private void processMessages(ArrayList<Peer.TransportWithSession> messages) throws InterruptedException {
		try (var sts = new StructuredTaskScope.ShutdownOnFailure()) {
			for (var m : messages) {
				sts.fork(() -> decryptAndEnqueue(m));
			}

			sts.join();
		}
	}

	/**
	 * Decrypts a transport message and enqueues it for reading
	 *
	 * @param inb the transport message to decrypt
	 * @return true if the message was successfully decrypted, false otherwise
	 */
	private boolean decryptAndEnqueue(Peer.TransportWithSession inb) {
		try {
			if (inb.session() == null)
				return false;

			if (inb.transport().content().remaining() < 16) {
				logger.log(WARNING, "Received transport message with invalid length");
				return false;
			}

			var result = ByteBuffer.allocate(inb.transport().content().remaining() - 16);
			inb.session().decryptTransportPacket(inb.transport(), result);
			result.flip();

			if (result.remaining() == 0) {
				logger.log(DEBUG, "Received keepalive");
			} else
				decryptedTransportQueue.add(result);

			return true;
		} catch (Throwable e) {
			logger.log(WARNING, "Error decrypting transport message (is the Device MTU big enough?)", e);
		}

		return false;
	}


	/**
	 * Sets the session. Requires that the peerLock be held.
	 */
	@GuardedBy("peerLock")
	private void setSession(@Nullable EstablishedSession session) {
		if (this.session != null)
			device.clearSessionIndex(this.session.localIndex());

		this.session = session;

		if (session != null)
			device.setPeerSessionIndex(connectionInfo.remoteStatic(), session.localIndex());

		setSessionCondition.signalAll();
	}

	private int getNewSessionIndex() {
		class SessionIndex {
			private static final AtomicInteger nextSessionIndex = new AtomicInteger(0);
		}

		int localIndex = SessionIndex.nextSessionIndex.getAndIncrement();
		if (this.session != null)
			device.clearSessionIndex(this.session.localIndex());
		device.setPeerSessionIndex(connectionInfo.remoteStatic(), localIndex);
		return localIndex;
	}

	public void receiveInitiation(InetSocketAddress address, MessageInitiation messageInitiationInboundMessage) {
		inboundHandshakeInitiationQueue.add(Map.entry(messageInitiationInboundMessage, address));
	}
}
