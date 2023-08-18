package ax.xz.wireguard.cli;

import ax.xz.raw.spi.Tun;
import ax.xz.raw.spi.TunProvider;
import ax.xz.wireguard.TunnelDeviceBond;
import ax.xz.wireguard.WireguardDevice;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ThreadLocalRandom;

public class WireguardTunnelCLI {
	public static void printHelp(String cmdline) {
		System.out.printf("usage: %s <file>\n", cmdline);
	}

	public static void main(String[] args) throws IOException, InterruptedException {
		if (args.length != 1) {
			printHelp(ProcessHandle.current().info().commandLine().orElse("wireguard-java"));
			System.exit(1);
		}

		WireGuardConfigParser.WireguardConfig config;
		try {
			config = WireGuardConfigParser.parseConfig(Files.readString(Path.of(args[0])));
		} catch (IOException e) {
			System.err.println("Failed to read config file: " + e.getMessage());
			System.exit(1);
			return;
		}

		try (
			var device = new WireguardDevice(config.interfaceConfig().privateKey());
			var tun = TunProvider.getProvider().open()
		) {
			tun.setMTU(1500);
			device.setPhysicalLayerMTU(tun.mtu());

			if (config.interfaceConfig().listenPort() != null)
				device.bind(new InetSocketAddress(config.interfaceConfig().listenPort()));

			for (var address : config.interfaceConfig().addressWithMask()) {
				tun.addSubnet(Tun.Subnet.ofMask(address.getKey(), address.getValue()));
			}

			for (var peer : config.peers()) {
				device.addPeer(
					peer.publicKey(),
					peer.presharedKey(),
					peer.persistentKeepAlive(),
					peer.endpoint()
				);
			}

			var coupling = new TunnelDeviceBond(device, tun);
			coupling.run();
		}
	}


	public static InetAddress getRandomLocalIP(boolean isIPv6) {
		try {
			byte[] ipBytes;
			if (isIPv6) {
				// Generate random IPv6 address
				ipBytes = new byte[16];
				ThreadLocalRandom.current().nextBytes(ipBytes);

				// Set the first byte to FE and the second byte to 80 to make it a link-local address
				ipBytes[0] = (byte) 0xFE;
				ipBytes[1] = (byte) 0x80;
				ipBytes[2] = 0;
				ipBytes[3] = 0;
				ipBytes[4] = 0;
				ipBytes[5] = 0;
				ipBytes[6] = 0;
				ipBytes[7] = 0;
			} else {
				// Generate random IPv4 address in the local range 192.168.x.x
				ipBytes = new byte[4];
				ThreadLocalRandom.current().nextBytes(ipBytes); // Only randomize the last two bytes
				ipBytes[0] = (byte) 192;
				ipBytes[1] = (byte) 168;
			}

			return InetAddress.getByAddress(ipBytes);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
