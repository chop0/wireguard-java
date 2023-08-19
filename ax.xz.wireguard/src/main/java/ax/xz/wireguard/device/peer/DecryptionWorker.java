package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.device.message.MessageTransport;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.StructuredTaskScope;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.WARNING;

class DecryptionWorker implements Runnable {
	private static final Logger logger = System.getLogger(DecryptionWorker.class.getName());

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
			logger.log(DEBUG, "Decryption worker interrupted");
		} finally {
			logger.log(DEBUG, "Decryption worker shutting down");
		}
	}

	/**
	 * Waits till at least one message is present in the queue.  When a message is present, drains the queue and returns a list
	 * of its prior contents.
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
	 * Decrypts all messages in the given list and puts them in the appropriate queue
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



	int getInboundTransportQueueSize() {
		return inboundTransportQueue.size();
	}

	int getDecryptedTransportQueueSize() {
		return decryptedTransportQueue.size();
	}
}
