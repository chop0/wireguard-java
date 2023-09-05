import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.device.WireguardDevice;
import ax.xz.packet.ICMPv6;
import ax.xz.packet.IPv6;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.concurrent.Executors;

class StressTest {

	public static void main(String[] args) throws Throwable {
		var keypairA = NoisePrivateKey.newPrivateKey();
		var keypairB = NoisePrivateKey.newPrivateKey();

		try (var a = new WireguardDevice(keypairA); var b = new WireguardDevice(keypairB)) {
			a.bind(new InetSocketAddress(InetAddress.getByName("::1"), 51281));
			b.addOrGetPeer(keypairA.publicKey(), Duration.ofSeconds(25), new InetSocketAddress(InetAddress.getByName("::1"), 51281));

			try (var executor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().uncaughtExceptionHandler((t, e) -> e.printStackTrace()).factory())) {
				executor.submit(a::run);
				executor.submit(b::run);

				var icmp = IPv6.of(
						(Inet6Address) InetAddress.getByName("4444::"),
						(Inet6Address) InetAddress.getByName("4444::"),
						ICMPv6.echoRequest());

				executor.submit(() -> {
					try {
						var buf = ByteBuffer.allocateDirect(a.physicalLayerMTU());

						while (!Thread.interrupted()) {
							buf.clear();
							icmp.write(buf);
							buf.flip();
							a.broadcastTransport(buf);
						}
					} catch (Throwable e) {
						e.printStackTrace();
					}

					return null;
				});

				executor.submit(() -> {
					try {
						while (!Thread.interrupted()) {
							try {
								a.receiveTransport();
							} catch (IllegalStateException e) {
								e.printStackTrace();
							}
						}
					} catch (Throwable e) {
						e.printStackTrace();
					}
				});

				executor.submit(() -> {
					try {
						var buf = ByteBuffer.allocateDirect(b.physicalLayerMTU());

						while (!Thread.interrupted()) {
							buf.clear();
							icmp.write(buf);
							buf.flip();
							b.broadcastTransport(buf);
						}
					} catch (Throwable e) {
						e.printStackTrace();
					}

					return null;
				});

				executor.submit(() -> {
					try {
						while (!Thread.interrupted()) {
							try {
								 b.receiveTransport();
							} catch (IllegalStateException e) {
								e.printStackTrace();
							}
						}
					} catch (Throwable e) {
						e.printStackTrace();
					}
				});

				while (!Thread.interrupted()) {
					System.out.println("a: " + a.getStats());
					System.out.println("b: " + b.getStats());
					Thread.sleep(1000);
				}
			}
		}
	}
}
