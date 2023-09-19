package ax.xz.wireguard.device;

import ax.xz.raw.spi.Tun;
import ax.xz.wireguard.util.PersistentTaskExecutor;

import java.io.IOException;
import java.util.concurrent.ScheduledThreadPoolExecutor;

import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;

public class TunnelDeviceBond {
	private static final Logger logger = System.getLogger(TunnelDeviceBond.class.getName());

	private final WireguardDevice device;
	private final Tun tunnel;

	public TunnelDeviceBond(WireguardDevice device, Tun tunnel) {
		this.device = device;
		this.tunnel = tunnel;
	}

	public void run() throws InterruptedException {
		// platform threads for performance
		try (var sts = new PersistentTaskExecutor<>(RuntimeException::new, logger, Thread.ofPlatform().factory())) {
			sts.submit(device::run);

			sts.submit("Tunnel read worker", () -> {
				int mtu = tunnel.mtu();

				while (!Thread.interrupted()) {
					var buffer = device.getBufferPool().acquire(mtu);

					try {
						tunnel.read(buffer.buffer());
						buffer.buffer().flip();
						device.broadcastTransportOutwards(buffer);
					} catch (IOException e) {
						logger.log(WARNING, "Error reading from tunnel", e);
					}
				}
			});

			sts.submit("Tunnel write worker", () -> {
				while (!Thread.interrupted()) {
					try (var transport = device.receiveIncomingTransport()) {
						tunnel.write(transport.buffer());
					} catch (IOException e) {
						logger.log(WARNING, "Error writing to tunnel", e);
					}
				}
			});

			try (var sch = new ScheduledThreadPoolExecutor(0, Thread.ofVirtual().factory())) {
				sch.scheduleAtFixedRate(() -> logger.log(INFO, device.getStats().toString()), 0, 10, java.util.concurrent.TimeUnit.SECONDS);

				sts.awaitTermination();
			}
		}
	}
}
