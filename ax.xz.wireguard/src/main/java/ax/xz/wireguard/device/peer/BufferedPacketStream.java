package ax.xz.wireguard.device.peer;

import ax.xz.raw.spi.BatchedDatagramSocket;
import ax.xz.raw.spi.BatchedDatagramSocketProvider;
import ax.xz.wireguard.device.message.transport.outgoing.EncryptedOutgoingTransport;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class BufferedPacketStream {
	private final BatchedDatagramSocket socket;
	private final Duration flushLatency;

	private Instant nextFlush;
	private final ThreadLocal<LinkedBlockingQueue<queued>> queue;


	public BufferedPacketStream(Duration flushLatency) {
		this.flushLatency = flushLatency;
		try {
			this.socket = BatchedDatagramSocketProvider.getProvider().open();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		nextFlush = Instant.now().plus(flushLatency);

		queue = ThreadLocal.withInitial(() -> {
			var ll = new LinkedBlockingQueue<queued>();
			Thread.startVirtualThread(() -> {
				while (!Thread.interrupted()) { // TODO this is FUCKING AWFUL commit suicide
					try {
						Thread.sleep(flushLatency.multipliedBy(2));
						maybeFlush(ll);
					} catch (InterruptedException e) {

					}
				}
			});

			return ll;
		});
	}

	public void transmit(EncryptedOutgoingTransport thing, InetSocketAddress dst) {
		var q = queue.get();
		q.add(new queued(dst, thing));
		maybeFlush(q);
	}

	private void maybeFlush(LinkedBlockingQueue<queued> q) {
		nextFlush = Instant.now().plus(flushLatency);

		try {
			var glizzy = new ArrayList<BatchedDatagramSocket.Packet>(q.size());
			var gobbler = new ArrayList<queued>(q.size());
			while (!q.isEmpty()) {
				var t = q.poll();
				if (t != null) {
					glizzy.add(t.packet);
					gobbler.add(t);
				}
			}

			socket.send(glizzy);

			gobbler.forEach(queued -> queued.ts.close());

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void close() {
		socket.close();
	}

	private record queued(InetSocketAddress dst, EncryptedOutgoingTransport ts, BatchedDatagramSocket.Packet packet) {
		public queued(InetSocketAddress dst, EncryptedOutgoingTransport ts) {
			this(dst, ts, new BatchedDatagramSocket.Packet(dst, ts.transmissiblePacket()));
		}
	}
}
