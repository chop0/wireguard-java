package ax.xz.wireguard.device;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.device.message.transport.incoming.DecryptedIncomingTransport;
import ax.xz.wireguard.device.message.tunnel.IncomingTunnelPacket;
import ax.xz.wireguard.device.message.tunnel.UninitialisedIncomingTunnelPacket;
import ax.xz.wireguard.util.Pool;
import ax.xz.wireguard.util.ReferenceCounted;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

public class TunPacketRouter implements Runnable {
	private final Pool pool;

	private final Tun tun;

	private final Set<TunPacketChannel> associatedChannels = ConcurrentHashMap.newKeySet();

	public TunPacketRouter(Pool pool, Tun tun) {
		this.pool = pool;
		this.tun = tun;
	}

	@Override
	public void run() {
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
