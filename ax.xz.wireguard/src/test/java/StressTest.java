//import ax.xz.wireguard.noise.keys.NoisePrivateKey;
//import ax.xz.wireguard.device.WireguardDevice;
//import ax.xz.packet.ICMP;
//import ax.xz.packet.IPv6;
//
//import java.net.Inet6Address;
//import java.net.InetAddress;
//import java.net.InetSocketAddress;
//import java.nio.ByteBuffer;
//import java.time.Duration;
//import java.util.concurrent.Executors;
//
//class StressTest {
//
//	public static void main(String[] args) throws Throwable {
//		var keypairA = NoisePrivateKey.newPrivateKey();
//		var keypairB = NoisePrivateKey.newPrivateKey();
//
//		try (var a = new WireguardDevice(keypairA); var b = new WireguardDevice(keypairB)) {
//			a.bind(new InetSocketAddress(InetAddress.getByName("::1"), 51281));
//			InetSocketAddress endpoint = new InetSocketAddress(InetAddress.getByName("::1"), 51281);
//			b.addPeer(keypairA.publicKey(), Duration.ofSeconds(25), endpoint);
//
//			try (var executor = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().uncaughtExceptionHandler((t, e) -> e.printStackTrace()).factory())) {
//				executor.submit(a::run);
//				executor.submit(b::run);
//
//				var icmp = IPv6.of(
//						(Inet6Address) InetAddress.getByName("4444::"),
//						(Inet6Address) InetAddress.getByName("4444::"),
//						ICMP.echoRequest());
//
//				executor.submit(() -> {
//					try {
//						var buf = dev.allocateDirect(a.receiveBufferSize());
//
//						while (!Thread.interrupted()) {
//							buf.clear();
//							icmp.write(buf);
//							buf.flip();
//							a.enqueueOnAll(buf);
//						}
//					} catch (Throwable e) {
//						e.printStackTrace();
//					}
//
//					return null;
//				});
//
//				executor.submit(() -> {
//					try {
//						while (!Thread.interrupted()) {
//							try {
//								a.receiveIncomingTransport();
//							} catch (IllegalStateException e) {
//								e.printStackTrace();
//							}
//						}
//					} catch (Throwable e) {
//						e.printStackTrace();
//					}
//				});
//
//				executor.submit(() -> {
//					try {
//						var buf = ByteBuffer.allocateDirect(b.receiveBufferSize());
//
//						while (!Thread.interrupted()) {
//							buf.clear();
//							icmp.write(buf);
//							buf.flip();
//							b.enqueueOnAll(buf);
//						}
//					} catch (Throwable e) {
//						e.printStackTrace();
//					}
//
//					return null;
//				});
//
//				executor.submit(() -> {
//					try {
//						while (!Thread.interrupted()) {
//							try {
//								 b.receiveIncomingTransport();
//							} catch (IllegalStateException e) {
//								e.printStackTrace();
//							}
//						}
//					} catch (Throwable e) {
//						e.printStackTrace();
//					}
//				});
//
//				while (!Thread.interrupted()) {
//					System.out.println("a: " + a.getStats());
//					System.out.println("b: " + b.getStats());
//					Thread.sleep(1000);
//				}
//			}
//		}
//	}
//}
