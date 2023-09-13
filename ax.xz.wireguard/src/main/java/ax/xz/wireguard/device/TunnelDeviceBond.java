package ax.xz.wireguard.device;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.util.PersistentTaskExecutor;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.*;

public class TunnelDeviceBond {
	private static final Logger logger = System.getLogger(TunnelDeviceBond.class.getName());

	private final WireguardDevice device;
	private final Tun tunnel;

	public TunnelDeviceBond(WireguardDevice device, Tun tunnel) throws IOException {
		this.device = device;
		this.tunnel = tunnel;
	}

	public void run() throws InterruptedException {
		try (var sts = new PersistentTaskExecutor<>("TunnelDeviceBond", RuntimeException::new, logger)) {
			sts.fork(() -> {
				device.run();
				return null;
			});
			sts.fork(() -> {
				int mtu = tunnel.mtu();
				while (!Thread.interrupted()) {
					try {
						var buffer = ByteBuffer.allocateDirect(mtu); // TODO:  optimize

						tunnel.read(buffer);
						buffer.flip();

						device.enqueueOnAll(buffer);
					} catch (IOException e) {
						logger.log(WARNING, "Error reading from tunnel", e);
						break;
					}
				}

				return null;
			});

			sts.fork(() -> {
				while (!Thread.interrupted()) {
					try {
						var transport = device.receiveTransport().order(ByteOrder.BIG_ENDIAN);
						tunnel.write(transport);
					} catch (IOException e) {
						logger.log(WARNING, "Error writing to tunnel", e);
					}
				}

				return null;
			});

			try (var sch = new ScheduledThreadPoolExecutor(0, Thread.ofVirtual().factory())) {
				sch.scheduleAtFixedRate(() -> logger.log(INFO, device.getStats().toString()), 0, 10, java.util.concurrent.TimeUnit.SECONDS);

				sts.join();
			}
		}
	}
}
