package ax.xz.wireguard.cli;

import ax.xz.wireguard.device.peer.Peer;
import ax.xz.wireguard.util.IPFilter;
import ax.xz.wireguard.util.IPUtils;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.net.*;
import java.time.Duration;
import java.util.*;

public class WireGuardConfigParser {
	public static WireguardConfig parseConfig(String configContent) throws UnknownHostException {
		Scanner scanner = new Scanner(configContent);
		InterfaceConfig interfaceConfig = null;
		List<Peer.PeerConnectionInfo> peers = new ArrayList<>();

		var sections = new ArrayList<String>();
		var currentSection = new StringBuilder();
		while (scanner.hasNextLine()) {
			String line = scanner.nextLine().trim();

			if (line.startsWith("[")) {
				sections.add(currentSection.toString());
				currentSection = new StringBuilder();
				currentSection.append(line).append("\n");
			} else {
				currentSection.append(line).append("\n");
			}
		}

		sections.add(currentSection.toString());

		for (var section : sections) {
			var firstLine = section.split("\n")[0].trim();

			if (firstLine.equals("[Interface]"))
				interfaceConfig = parseInterfaceConfig(new Scanner(section));
			else if (firstLine.equals("[Peer]"))
				peers.add(parsePeerConfig(new Scanner(section)));
		}

		if (interfaceConfig == null) {
			throw new RuntimeException("No [Interface] section found in the config.");
		}

		return new WireguardConfig(interfaceConfig, peers);
	}

	private static InterfaceConfig parseInterfaceConfig(Scanner scanner) throws UnknownHostException {
		Set<Map.Entry<InetAddress, InetAddress>> addresses = new HashSet<>();
		String privateKey = null;
		Integer listenPort = null;

		scanner.nextLine();
		while (scanner.hasNextLine()) {
			String line = scanner.nextLine().trim();

			if (line.isEmpty() || line.startsWith("[")) {
				break;
			}

			String[] parts = line.split("=", 2);
			if (parts.length != 2) {
				continue;
			}

			switch (parts[0].trim()) {
				case "Address" -> {
					var addressWithPrefix = parts[1].trim().split("/");
					var addr = InetAddress.getByName(addressWithPrefix[0]);

					if (addressWithPrefix.length == 1) {
						addresses.add(Map.entry(addr, IPUtils.fullNetmask(addr instanceof Inet6Address)));
					} else {
						var maskString = addressWithPrefix[1];

						InetAddress mask;
						if (maskString.contains(".")) {
							mask = InetAddress.getByName(maskString);
						} else {
							mask = IPUtils.netmaskFromPrefixLength(Integer.parseInt(maskString), addr instanceof Inet6Address);
						}

						addresses.add(Map.entry(addr, mask));
					}
				}
				case "PrivateKey" -> privateKey = parts[1].trim();
				case "ListenPort" -> listenPort = Integer.parseInt(parts[1].trim());
			}
		}

		Objects.requireNonNull(privateKey, "No private key found in the [Interface] section.");

		return new InterfaceConfig(addresses, NoisePrivateKey.fromBase64(privateKey), listenPort);
	}

	private static Peer.PeerConnectionInfo parsePeerConfig(Scanner scanner) throws UnknownHostException {
		String publicKey = null;
		String presharedKey = null;
		Set<Map.Entry<InetAddress, Integer>> allowedIPs = new HashSet<>();
		InetSocketAddress endpoint = null;
		Duration persistentKeepAlive = null;

		scanner.nextLine();
		while (scanner.hasNextLine()) {
			String line = scanner.nextLine().trim();

			if (line.isEmpty() || line.startsWith("[")) {
				break;
			}

			String[] parts = line.split("=", 2);
			if (parts.length != 2) {
				continue;
			}

			switch (parts[0].trim()) {
				case "PublicKey" -> publicKey = parts[1].trim();
				case "AllowedIPs" -> {
					String[] ips = parts[1].split(",");
					for (String ip : ips) {
						if (!ip.contains("/")) {
							allowedIPs.add(Map.entry(InetAddress.getByName(ip.trim()), 32));
						} else {
							var afterSlash = ip.split("/")[1].trim();
							allowedIPs.add(Map.entry(InetAddress.getByName(ip.split("/")[0].trim()), Integer.parseInt(afterSlash)));
						}
					}
				}
				case "PresharedKey" -> presharedKey = parts[1].trim();
				case "Endpoint" -> {
					try {
						endpoint = parseIsr(parts[1].trim());
					} catch (IllegalArgumentException ex) {
						endpoint = new InetSocketAddress(parts[1].trim(), 51280);
					}
				}
				case "PersistentKeepalive" -> persistentKeepAlive = Duration.ofSeconds(Integer.parseInt(parts[1].trim()));
			}
		}

		if (publicKey == null) {
			throw new RuntimeException("Incomplete [Peer] section in the config.");
		}

		var filter = allowedIPs.isEmpty() ? IPFilter.allowingAll() : new IPFilter();
		for (var entry : allowedIPs) {
			filter.insert(entry.getKey(), entry.getValue());
		}

		return new Peer.PeerConnectionInfo(
			NoisePublicKey.fromBase64(publicKey),
			presharedKey == null ? NoisePresharedKey.zero() : NoisePresharedKey.fromBase64(presharedKey),
			endpoint,
			persistentKeepAlive == null ? Duration.ofDays(1_000_000_000) : persistentKeepAlive,
			filter
		);
	}

	private static InetSocketAddress parseIsr(String hostPort) throws UnknownHostException {
		if (hostPort == null || hostPort.isEmpty()) {
			throw new IllegalArgumentException("Invalid host:port format");
		}

		int lastColonIndex = hostPort.lastIndexOf(':');
		if (lastColonIndex < 0 || lastColonIndex == hostPort.length() - 1) {
			throw new IllegalArgumentException("Invalid host:port format");
		}

		String host = hostPort.substring(0, lastColonIndex);
		String portStr = hostPort.substring(lastColonIndex + 1);

		int port;
		try {
			port = Integer.parseInt(portStr);
		} catch (NumberFormatException e) {
			throw new IllegalArgumentException("Invalid port number");
		}


		return new InetSocketAddress(InetAddress.getByName(host), port);
	}

	public record WireguardConfig(InterfaceConfig interfaceConfig, List<Peer.PeerConnectionInfo> peers) {}
	public record InterfaceConfig(Set<Map.Entry<InetAddress, InetAddress>> addressWithMask, NoisePrivateKey privateKey, Integer listenPort) {}
}
