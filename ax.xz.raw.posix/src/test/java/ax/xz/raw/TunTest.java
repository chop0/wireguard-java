package ax.xz.raw;

import ax.xz.packet.IPv6;
import ax.xz.packet.UDP;
import ax.xz.raw.posix.POSIXTunProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

public class TunTest {
	private static final Inet6Address LOCALHOST6, TEST_ADDRESS;

	static {
		try {
			LOCALHOST6 = (Inet6Address) Inet6Address.getByName("::1");
			TEST_ADDRESS = (Inet6Address) Inet6Address.getByName("abcd:ef01:2345:6789:abcd:ef01:2345:6789");
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	@DisplayName("Should be able to receive a UDP datagram")
	@Test
	public void testRead() throws IOException {
		var packetContents = "Hello, world!";
		var javaSocketAddress = new InetSocketAddress(LOCALHOST6, 1234);
		var rawSocketAddress = new InetSocketAddress(TEST_ADDRESS, 1234);

		try (var datagramListener = DatagramChannel.open(StandardProtocolFamily.INET6); var tun = new POSIXTunProvider().open()) {
			tun.addAddress(rawSocketAddress.getAddress());

			datagramListener.bind(javaSocketAddress);
			datagramListener.connect(rawSocketAddress);

			datagramListener.write(ByteBuffer.wrap(packetContents.getBytes(StandardCharsets.UTF_8)));

			// read the packet we just sent
			var buf = ByteBuffer.allocate(1500);
			var packet = assertTimeoutPreemptively(Duration.ofMillis(50), () -> {
				for (; ; ) {
					buf.clear();
					tun.read(buf);
					buf.flip();

					try {
						var result = IPv6.parse(buf);
						if (result.payload() instanceof UDP) {
							return result;
						}
					} catch (Exception e) {
					}

					System.err.println("Received extraneous packet;  ignoring");
				}
			}, "Tun should receive packet");

			assertEquals(javaSocketAddress.getAddress(), packet.source(), "Source address should match");
			assertEquals(rawSocketAddress.getAddress(), packet.destination(), "Destination address should match");

			var payload = (UDP) packet.payload();
			assertEquals(javaSocketAddress.getPort(), payload.sourcePort(), "Source port should match");
			assertEquals(rawSocketAddress.getPort(), payload.destinationPort(), "Destination port should match");

			assertEquals(8 + packetContents.length(), packet.payloadLength(), "Payload length should match");
			assertEquals(packetContents, new String(payload.data(), StandardCharsets.UTF_8), "Payload contents should match");
		}
	}

	@DisplayName("Should be able to send a UDP datagram")
	@Test
	public void testWrite() throws IOException {
		var packetContents = "Hello, world!";
		var javaSocketAddress = new InetSocketAddress(LOCALHOST6, 1234);
		var rawSocketAddress = new InetSocketAddress(TEST_ADDRESS, 1234);

		try (var datagramListener = DatagramChannel.open(StandardProtocolFamily.INET6); var tun = new POSIXTunProvider().open()) {
			tun.addAddress(rawSocketAddress.getAddress());

			datagramListener.bind(javaSocketAddress);
			datagramListener.connect(rawSocketAddress);

			var payload = UDP.datagram(rawSocketAddress.getPort(), javaSocketAddress.getPort(), packetContents.getBytes(StandardCharsets.UTF_8));
			var packet = IPv6.of((Inet6Address) rawSocketAddress.getAddress(), (Inet6Address) javaSocketAddress.getAddress(), payload);

			var buf = ByteBuffer.allocate(1500);
			packet.write(buf);
			buf.flip();
			tun.write(buf);

			buf.clear();
			assertTimeoutPreemptively(Duration.ofMillis(50), () -> datagramListener.read(buf), "Listener should receive packet");
			buf.flip();

			assertEquals(buf.remaining(), packetContents.length(), "Payload length should match");
			assertEquals(packetContents, StandardCharsets.UTF_8.decode(buf).toString(), "Payload contents should match");
		}
	}
}
