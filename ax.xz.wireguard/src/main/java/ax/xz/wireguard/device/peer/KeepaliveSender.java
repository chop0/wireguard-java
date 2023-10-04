package ax.xz.wireguard.device.peer;

import ax.xz.wireguard.util.ThreadLocalPool;

import javax.annotation.Nullable;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

import static java.lang.System.Logger.Level.DEBUG;

/**
 * This class sends keepalives to the peer.
 */
class KeepaliveSender implements Runnable {
	private static final System.Logger logger = System.getLogger(KeepaliveSender.class.getName());
	private static final MemorySegment keepalivePacket = MemorySegment.ofBuffer(ByteBuffer.allocateDirect(0));

	private final SessionManager sessionManager;
	private final PeerTransportManager peerTransportManager;

	KeepaliveSender(SessionManager sessionManager, PeerTransportManager peerTransportManager) {
		this.sessionManager = sessionManager;
		this.peerTransportManager = peerTransportManager;

	}

	private KeepaliveRecord previousKeepalive = KeepaliveRecord.of(null);

	@Override
	public void run() {
		sessionManager.lock.lock();

		try (var tlp = new ThreadLocalPool(2)) {
			while (!Thread.interrupted()) {
				var session = sessionManager.tryGetSessionNow();
				if (previousKeepalive.needsKeepalive(session)) {
					peerTransportManager.sendOutgoingTransport(tlp, keepalivePacket);
					previousKeepalive = KeepaliveRecord.of(session);
				}

				sessionManager.condition.await(previousKeepalive.timeTillExpiration().toMillis(), TimeUnit.MILLISECONDS);
			}
		} catch (InterruptedException e) {
			logger.log(DEBUG, "Keepalive sender interrupted", e);
			Thread.currentThread().interrupt();
		} finally {
			sessionManager.lock.unlock();
		}
	}

	record KeepaliveRecord(@Nullable EstablishedSession session, Instant time) {
		static KeepaliveRecord of(@Nullable EstablishedSession session) {
			return new KeepaliveRecord(session, Instant.now());
		}

		/**
		 * Returns true if the given session needs another keepalive, based upon this record.
		 * <ul>
		 *     <li>If the given session is null, then a keepalive is not needed.</li>
		 *     <li>If the given session is not null, but is not the same as the session in this record, then a keepalive is needed.</li>
		 *     <li>If the given session is not null, and is the same as the session in this record, but the time in this record is more than the keepalive interval ago, then a keepalive is needed.</li>
		 * </ul>
		 *
		 * @param currentSession the session to check
		 * @return true if this record is still valid, and false if another keepalive needs to be sent
		 */
		boolean needsKeepalive(@Nullable EstablishedSession currentSession) {
			if (currentSession == null)
				return false;

			return this.session == currentSession && Duration.between(time, Instant.now()).compareTo(currentSession.getKeepaliveInterval()) < 0;
		}

		/**
		 * Returns the time that this record will expire, or {@link ChronoUnit#FOREVER} if it will never expire (for
		 * a null session).
		 */
		Duration timeTillExpiration() {
			if (session == null)
				return ChronoUnit.FOREVER.getDuration();
			else
				return Duration.between(Instant.now(), time.plus(session.getKeepaliveInterval()));
		}
	}
}
