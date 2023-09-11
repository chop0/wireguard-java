package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Adds and removes subnets from an interface using the ip command.
 */
public class IpTunInterfaceConfigurer implements TunInterfaceConfigurer {
	private String[] ipSubnetModificationCommand(Tun.Subnet subnet, String deviceName, String action) {
		return new String[]{
			"ip",
			subnet.isIPv4() ? "-4" : "-6",
			"addr",
			action,
			subnet.toCIDRString(),
			"dev",
			deviceName
		};
	}

	@Override
	public void addSubnet(String ifName, Tun.Subnet subnet) throws IOException {
		try {
			TunInterfaceConfigurer.runCommand(ipSubnetModificationCommand(subnet, ifName, "add"));
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void removeSubnet(String ifName, Tun.Subnet subnet) throws IOException {
		try {
			TunInterfaceConfigurer.runCommand(ipSubnetModificationCommand(subnet, ifName, "del"));
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void up(String ifName) throws IOException {
		try {
			TunInterfaceConfigurer.runCommand("ip", "link", "set", "dev", ifName, "up");
		} catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

	@Override
	public Set<Tun.Subnet> subnets(String ifName) throws IOException {
		try {
			return TunInterfaceConfigurer.runCommand("ip", "address", "show", "dev", ifName).lines()
				.map(String::strip)
				.filter(s -> s.startsWith("inet"))
				.map(this::parseIpAddressLine)
				.collect(Collectors.toSet());
		} catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

	private Tun.Subnet parseIpAddressLine(String line) {
		var parts = line.split(" ")[1].split("/");

		try {
			return new Tun.Subnet(InetAddress.getByName(parts[0]), Integer.parseInt(parts[1]));
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}
}
