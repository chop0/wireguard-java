package ax.xz.raw;

import ax.xz.packet.IPv4;
import ax.xz.packet.IPv6;
import ax.xz.packet.UDP;
import ax.xz.raw.posix.POSIXTunProvider;
import ax.xz.raw.spi.Tun;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

public class TunTest {
	private static final Inet4Address LOCALHOST4, TEST_ADDRESS4;
	private static final Inet6Address LOCALHOST6, TEST_ADDRESS6;

	static {
		try {
			LOCALHOST4 = (Inet4Address) Inet4Address.getByName("127.0.0.1");
			LOCALHOST6 = (Inet6Address) Inet6Address.getByName("::1");

			TEST_ADDRESS4 = (Inet4Address) Inet4Address.getByName("1.2.3.4");
			TEST_ADDRESS6 = (Inet6Address) Inet6Address.getByName("abcd:ef01:2345:6789:abcd:ef01:2345:6789");
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	@DisplayName("Tun provider should be available")
	@Test
	public void testIsAvailable() {
		assertTrue(new POSIXTunProvider().isAvailable(), "Tun should be available");
	}

	@DisplayName("Should be able to set the MTU")
	@Test
	public void testSetMTU() throws IOException {
		try (var tun = new POSIXTunProvider().open()) {
			tun.setMTU(1500);
			assertEquals(1500, tun.mtu(), "MTU should match");
		}
	}

	@DisplayName("Should be able to add and remove addresses")
	@Test
	public void testAddRemoveAddress() throws IOException {
		try (var tun = new POSIXTunProvider().open()) {
			tun.addAddress(LOCALHOST4);
			tun.addAddress(LOCALHOST6);

			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 32)), "Tun should have ipv4 address");
			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST6, 128)), "Tun should have ipv6 address");

			tun.removeAddress(LOCALHOST6);
			assertFalse(tun.subnets().contains(new Tun.Subnet(LOCALHOST6, 128)), "Tun should not have ipv6 address");
			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 32)), "Tun should still have ipv4 address");

			tun.removeAddress(LOCALHOST4);
			assertFalse(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 32)), "Tun should not have ipv4 address");
		}
	}

	@DisplayName("Should be able to add and remove subnets")
	@Test
	public void testAddRemoveSubnet() throws IOException {
		try (var tun = new POSIXTunProvider().open()) {
			tun.addSubnet(new Tun.Subnet(LOCALHOST4, 24));
			tun.addSubnet(new Tun.Subnet(LOCALHOST6, 64));

			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 24)), "Tun should have ipv4 subnet");
			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST6, 64)), "Tun should have ipv6 subnet");

			tun.removeSubnet(new Tun.Subnet(LOCALHOST6, 64));
			assertFalse(tun.subnets().contains(new Tun.Subnet(LOCALHOST6, 64)), "Tun should not have ipv6 subnet");
			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 24)), "Tun should still have ipv4 subnet");

			tun.removeSubnet(new Tun.Subnet(LOCALHOST4, 24));
			assertFalse(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 24)), "Tun should not have ipv4 subnet");

			tun.addSubnet(new Tun.Subnet(LOCALHOST4, 24));
			tun.addSubnet(new Tun.Subnet(LOCALHOST6, 64));

			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 24)), "Tun should have ipv4 subnet");
			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST6, 64)), "Tun should have ipv6 subnet");

			tun.removeSubnet(new Tun.Subnet(LOCALHOST4, 24));
			assertFalse(tun.subnets().contains(new Tun.Subnet(LOCALHOST4, 24)), "Tun should not have ipv4 subnet");
			assertTrue(tun.subnets().contains(new Tun.Subnet(LOCALHOST6, 64)), "Tun should still have ipv6 subnet");

			tun.removeSubnet(new Tun.Subnet(LOCALHOST6, 64));
			assertFalse(tun.subnets().contains(new Tun.Subnet(LOCALHOST6, 64)), "Tun should not have ipv6 subnet");
		}
	}

	@DisplayName("Should be able to receive a UDP datagram over IPv6")
	@Test
	public void testRead6() throws IOException {
		var packetContents = "Hello, world!";
		var javaSocketAddress = new InetSocketAddress(LOCALHOST6, 1234);
		var rawSocketAddress = new InetSocketAddress(TEST_ADDRESS6, 1234);

		try (var datagramListener = DatagramChannel.open(StandardProtocolFamily.INET6); var tun = new POSIXTunProvider().open()) {
			tun.addAddress(rawSocketAddress.getAddress());

			datagramListener.bind(javaSocketAddress);

			datagramListener.send(ByteBuffer.wrap(packetContents.getBytes(StandardCharsets.UTF_8)), rawSocketAddress);

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

	@DisplayName("Should be able to receive a UDP datagram over IPv4")
	@Test
	public void testRead4() throws IOException {
		var packetContents = "Hello, world!";
		var rawSocketAddress = new InetSocketAddress(TEST_ADDRESS4, 1234);

		try (var datagramListener = DatagramChannel.open(StandardProtocolFamily.INET); var tun = new POSIXTunProvider().open()) {
			tun.addAddress(rawSocketAddress.getAddress());
			datagramListener.send(ByteBuffer.wrap(packetContents.getBytes(StandardCharsets.UTF_8)), rawSocketAddress);

			// read the packet we just sent
			var buf = ByteBuffer.allocate(1500);
			var packet = assertTimeoutPreemptively(Duration.ofMillis(50), () -> {
				for (; ; ) {
					buf.clear();
					tun.read(buf);
					buf.flip();

					try {
						var result = IPv4.parse(buf);
						if (result.payload() instanceof UDP) {
							return result;
						}
					} catch (Exception e) {
					}

					System.err.println("Received extraneous packet;  ignoring");
				}
			}, "Tun should receive packet");

			assertEquals(rawSocketAddress.getAddress(), packet.destination(), "Destination address should match");

			var payload = (UDP) packet.payload();
			assertEquals(rawSocketAddress.getPort(), payload.destinationPort(), "Destination port should match");

			assertEquals(packetContents, new String(payload.data(), StandardCharsets.UTF_8), "Payload contents should match");
		}
	}


	@DisplayName("Should be able to send a UDP datagram over IPv6")
	@Test
	public void testWrite6() throws IOException {
		var packetContents = "Hello, world!";
		var javaSocketAddress = new InetSocketAddress(LOCALHOST6, 1234);
		var rawSocketAddress = new InetSocketAddress(TEST_ADDRESS6, 1234);

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

	@DisplayName("Should be able to send a UDP datagram over IPv4")
	@Test
	public void testWrite4() throws IOException {
		var packetContents = "Hello, world!";
		var javaSocketAddress = new InetSocketAddress(LOCALHOST4, 1234);
		var rawSocketAddress = new InetSocketAddress(TEST_ADDRESS4, 1234);

		try (var datagramListener = DatagramChannel.open(StandardProtocolFamily.INET); var tun = new POSIXTunProvider().open()) {
			tun.addAddress(rawSocketAddress.getAddress());

			datagramListener.bind(javaSocketAddress);
			datagramListener.connect(rawSocketAddress);

			var payload = UDP.datagram(rawSocketAddress.getPort(), javaSocketAddress.getPort(), packetContents.getBytes(StandardCharsets.UTF_8));
			var packet = IPv4.of((Inet4Address) rawSocketAddress.getAddress(), (Inet4Address) javaSocketAddress.getAddress(), payload);

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
