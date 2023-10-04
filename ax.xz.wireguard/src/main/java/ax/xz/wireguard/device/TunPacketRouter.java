package ax.xz.wireguard.device;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.device.message.tunnel.UninitialisedIncomingTunnelPacket;
import ax.xz.wireguard.util.SharedPool;
import ax.xz.wireguard.util.ReferenceCounted;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

public class TunPacketRouter implements AutoCloseable {
	private final SharedPool pool;

	private final Tun tun;

	private final Set<TunPacketChannel> associatedChannels = ConcurrentHashMap.newKeySet();

	private final Thread thread;

	public TunPacketRouter(SharedPool pool, Tun tun) {
		this.pool = pool;
		this.tun = tun;

		this.thread = new Thread(this::run, "TunPacketRouter");
	}

	private void run() {
		while (!Thread.interrupted()) {
			var buffer = new UninitialisedIncomingTunnelPacket(pool.acquire());

			try (var packet = ReferenceCounted.of(buffer.initialise(tun::read))) {
				for (var channel : associatedChannels) {
					channel.queue.offer(packet.retain());
				}
			} catch (IOException e) {
				buffer.close();
				throw new RuntimeException(e);
			}
		}
	}

	public TunPacketChannel openChannel() {
		var channel = new TunPacketChannel();
		associatedChannels.add(channel);
		return channel;
	}

	@Override
	public void close() throws InterruptedException {
		thread.interrupt();
		thread.join();
	}

	public class TunPacketChannel implements AutoCloseable {
		private final LinkedBlockingQueue<ReferenceCounted<IncomingTunnelPacket>> queue = new LinkedBlockingQueue<>();

		public ReferenceCounted<IncomingTunnelPacket> take() throws InterruptedException {
			return queue.take();
		}

		public void send(DecryptedIncomingTransport transport) throws IOException {
			tun.write(transport.plaintextBuffer().asByteBuffer());
		}

		@Override
		public void close() {
			associatedChannels.remove(this);
		}
	}
}
