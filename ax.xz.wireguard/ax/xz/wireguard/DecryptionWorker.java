package ax.xz.wireguard;

import org.slf4j.Logger;

import javax.crypto.BadPaddingException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.StructuredTaskScope;

class DecryptionWorker implements Runnable {
	private static final Logger logger = ScopedLogger.getLogger(DecryptionWorker.class);

	private final SessionManager sessionManager;

	// a queue of inbound transport messages
	private final LinkedBlockingQueue<Peer.TransportWithSession> inboundTransportQueue = new LinkedBlockingQueue<>();

	private final LinkedBlockingQueue<ByteBuffer> decryptedTransportQueue = new LinkedBlockingQueue<>();

	DecryptionWorker(SessionManager sessionManager) {
		this.sessionManager = sessionManager;
	}

	void receiveTransport(MessageTransport transport) {
		var currentSession = sessionManager.tryGetSessionNow();
		if (currentSession == null)
			return;

		inboundTransportQueue.add(new Peer.TransportWithSession(transport, currentSession));
	}

	/**
	 * Removes a decrypted transport message from the queue, and waits if none is present
	 * @return decrypted transport packet received
	 * @throws InterruptedException if the thread is interrupted whilst waiting
	 */
	ByteBuffer receiveDecryptedTransport() throws InterruptedException {
		return decryptedTransportQueue.take();
	}

	@Override
	public void run() {
		try {
			while (!Thread.interrupted()) {
				processMessages(awaitInboundMessages());
			}
		} catch (InterruptedException e) {
			logger.debug("Decryption worker interrupted");
		} finally {
			logger.debug("Decryption worker shutting down");
		}
	}

	/**
	 * Waits till at least one message is present in the queue.  When a message is present, drains the queue and returns a list
	 * of its prior contents.
	 * @return A list containing all messages received since the last call
	 * @throws InterruptedException
	 */
	private ArrayList<Peer.TransportWithSession> awaitInboundMessages() throws InterruptedException {
		var messages = new ArrayList<Peer.TransportWithSession>(inboundTransportQueue.size());
		messages.add(inboundTransportQueue.take());
		inboundTransportQueue.drainTo(messages);
		return messages;
	}

	/**
	 * Decrypts all messages in the given list and puts them in the appropriate queue
	 * @param messages the messages to decrypt
	 * @throws InterruptedException
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
				logger.warn("Received transport message with invalid length");
				return false;
			}

			var result = ByteBuffer.allocate(inb.transport().content().remaining() - 16);
			inb.session().decryptTransportPacket(inb.transport(), result);
			result.flip();

			if (result.remaining() == 0) {
				logger.debug("Received keepalive");
			} else
				decryptedTransportQueue.add(result);

			return true;
		} catch (Throwable e) {
			logger.warn("Error decrypting transport message (is the Device MTU big enough?)", e);
		}

		return false;
	}



	int getInboundTransportQueueSize() {
		return inboundTransportQueue.size();
	}

	int getDecryptedTransportQueueSize() {
		return decryptedTransportQueue.size();
	}
}
