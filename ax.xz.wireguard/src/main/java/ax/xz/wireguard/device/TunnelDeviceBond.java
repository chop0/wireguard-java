package ax.xz.wireguard.device;

import ax.xz.raw.spi.RawSocket;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.System.Logger.Level.WARNING;

public class TunnelDeviceBond {
	private static final Logger logger = System.getLogger(TunnelDeviceBond.class.getName());

	private final WireguardDevice device;
	private final RawSocket tunnel;

	public TunnelDeviceBond(WireguardDevice device, RawSocket tunnel) {
		this.device = device;
		this.tunnel = tunnel;

		device.setPhysicalLayerMTU(tunnel.mtu());
	}

	public void run() throws InterruptedException {
		device.setPhysicalLayerMTU(tunnel.mtu() + 40 + 16);

		try (var sts = new PersistentTaskExecutor<>("TunnelDeviceBond", RuntimeException::new, logger)) {
			sts.fork(() -> {
				device.run();
				return null;
			});
			sts.fork(() -> {
				var buffer = ByteBuffer.allocateDirect(tunnel.mtu()); // reserve room for header

				while (!Thread.interrupted()) {
					try {
						// read
						buffer.clear();
						tunnel.read(buffer);
						buffer.flip();

						device.broadcastTransport(buffer);
					} catch (IOException e) {
						logger.log(WARNING, "Error reading from tunnel", e);
						break;
					}
				}

				return null;
			});

			sts.fork(() -> {
				while (!Thread.interrupted()) {
					// write
					var transport = device.receiveTransport().order(ByteOrder.BIG_ENDIAN);
					tunnel.write(transport);
				}

				return null;
			});

			try (var sch = new ScheduledThreadPoolExecutor(0, Thread.ofVirtual().factory())) {
				sch.scheduleAtFixedRate(() -> logger.log(DEBUG, device.getStats().toString()), 0, 1, java.util.concurrent.TimeUnit.SECONDS);

				sts.join();
			}
		}
	}
}
