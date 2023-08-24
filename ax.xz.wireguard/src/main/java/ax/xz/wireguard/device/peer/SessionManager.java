package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.wireguard.device.message.MessageInitiation;
import ax.xz.wireguard.device.message.MessageResponse;
import ax.xz.wireguard.device.message.MessageTransport;

import javax.annotation.Nullable;
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
import java.util.concurrent.locks.ReentrantLock;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

final class SessionManager extends SessionManagerBase {
	private static final int HANDSHAKE_ATTEMPTS = 5;

	private static final Logger logger = System.getLogger(SessionManager.class.getName());

	// A queue of inbound handshake response messages
	private final LinkedBlockingQueue<MessageResponse> inboundHandshakeResponseQueue = new LinkedBlockingQueue<>();

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

	// The current session.  Null iff no session is established and a handshake has not begun. This is protected by peerLock.
	private EstablishedSession session;


	SessionManager(WireguardDevice device, Peer.PeerConnectionInfo connectionInfo) {
		super(device, connectionInfo);
		this.connectionInfo = connectionInfo;
		this.device = device;
	}

	@Override
	protected Instant currentSessionExpiration() {
		var session = tryGetSessionNow();
		if (session == null)
			return Instant.MAX;
		else
			return session.expiration();
	}

	@Override
	protected Duration keepaliveInterval() {
		var session = tryGetSessionNow();
		if (session == null)
			return Duration.ofMillis(Long.MAX_VALUE);
		else
			return session.keepaliveInterval();
	}

	private final ReentrantLock initiationLock = new ReentrantLock(); // so we dont have multiple handshake responses at once

	@Override
	protected void attemptSessionRecoveryIfRequired() throws InterruptedException {
		initiationLock.lock();

		try {
			var oldSession = tryGetSessionNow();
			if (!(oldSession == null || oldSession.isExpired())) {
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

					var response = inboundHandshakeResponseQueue.poll(5, TimeUnit.SECONDS);
					if (response == null) {
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
		} finally {
			initiationLock.unlock();
		}
	}

	@Override
	protected void processHandshakeInitiationMessage() throws InterruptedException {
		var message = inboundHandshakeInitiationQueue.take();
		var initiation = message.getKey();
		var origin = message.getValue();

		try {
			setSession(HandshakeResponder.respond(device, initiation, connectionInfo.keepaliveInterval(), origin, getNewSessionIndex()));
			logger.log(INFO, "Completed handshake (responder)");
		} catch (IOException e) {
			logger.log(WARNING, "Failed to complete handshake (responder)", e);
			killSession();
		}
	}

	@Override
	protected void processTransportMessages() throws InterruptedException {
		processMessages(awaitInboundMessages());
	}

	@Override
	protected void sendKeepaliveIfNeeded() {
		var session = tryGetSessionNow();
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
		inboundHandshakeResponseQueue.add(message);
	}

	/**
	 * Enqueues an inbound handshake initiation message to be processed
	 *
	 * @param address                         the address the message was received from
	 * @param messageInitiationInboundMessage the message to enqueue
	 */
	void receiveInitiation(InetSocketAddress address, MessageInitiation messageInitiationInboundMessage) {
		inboundHandshakeInitiationQueue.add(Map.entry(messageInitiationInboundMessage, address));
	}

	/**
	 * Enqueues an inbound transport message to be processed
	 *
	 * @param transport the transport message to enqueue
	 */
	void receiveTransport(MessageTransport transport) {
		// no use waiting for a session, since if the session is not established, we will not be able to decrypt the message
		// because any sessions created in the future will have a different keypair
		var currentSession = tryGetSessionNow();
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
	private void setSession(@Nullable EstablishedSession session) {
		lock.lock();

		try {
			if (this.session != null)
				device.clearSessionIndex(this.session.localIndex());

			this.session = session;

			if (session != null)
				device.setPeerSessionIndex(connectionInfo.remoteStatic(), session.localIndex());

			condition.signalAll();
		} finally {
			lock.unlock();
		}
	}


	/**
	 * Returns the current session, or null if no session is established.
	 */
	@Nullable EstablishedSession tryGetSessionNow() {
		return session;
	}

	/**
	 * Marks the session as dead.  Requires that the peerLock be held.
	 */
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
}
