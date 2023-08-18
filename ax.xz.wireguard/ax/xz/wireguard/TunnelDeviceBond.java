package ax.xz.wireguard;

import ax.xz.raw.spi.RawSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class TunnelDeviceBond {
	private static final Logger logger = LoggerFactory.getLogger(TunnelDeviceBond.class);

	private final WireguardDevice device;
	private final RawSocket tunnel;

	public TunnelDeviceBond(WireguardDevice device, RawSocket tunnel) {
		this.device = device;
		this.tunnel = tunnel;

		device.setPhysicalLayerMTU(tunnel.mtu());
	}

	public void run() throws InterruptedException {
		device.setPhysicalLayerMTU(tunnel.mtu() + 40 + 16);

		try (var sts = new WorkerThreadScope()) {
			sts.fork(() -> {
				device.main();
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
						logger.warn("Error reading from tunnel", e);
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

			while (!Thread.interrupted() && !sts.isShutdown()) {
				logger.debug(device.getStats().toString());
				Thread.sleep(1000);
			}

			sts.join();
		}
	}
}
