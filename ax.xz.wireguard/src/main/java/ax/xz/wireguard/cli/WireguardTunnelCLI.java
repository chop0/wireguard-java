package ax.xz.wireguard.cli;

import ax.xz.raw.spi.Tun;
import ax.xz.raw.spi.TunProvider;
import ax.xz.wireguard.device.TunnelDeviceBond;
import ax.xz.wireguard.device.WireguardDevice;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.lang.System.Logger.Level.*;

public class WireguardTunnelCLI {
	private static final System.Logger logger = System.getLogger(WireguardTunnelCLI.class.getName());

	public static void printHelp(String cmdline) {
		logger.log(ERROR, "usage: %s <file>\n", cmdline);
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
			logger.log(ERROR, "Failed to read config file: " + e.getMessage());
			System.exit(1);
			return;
		}

		try (
				var device = new WireguardDevice(config.interfaceConfig().privateKey());
				var tun = TunProvider.getProvider().open()
		) {
			logger.log(DEBUG, "Opened tun device {0}", tun.toString());
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
}
