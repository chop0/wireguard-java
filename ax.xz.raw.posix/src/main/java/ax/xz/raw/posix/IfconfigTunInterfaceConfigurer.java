package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Set;
import java.util.stream.Collectors;

import static ax.xz.raw.spi.Tun.Subnet.convertNetmaskToCIDR;

/**
 * Adds and removes subnets from an interface using the ip command.
 */
public class IfconfigTunInterfaceConfigurer implements TunInterfaceConfigurer {

	@Override
	public void addSubnet(String ifName, Tun.Subnet subnet) throws IOException {
		try {
			if (subnet.isIPv4())
				TunInterfaceConfigurer.runCommand("ifconfig", ifName, "inet", subnet.toCIDRString(), subnet.address().getHostAddress(), "alias");
			else
				TunInterfaceConfigurer.runCommand("ifconfig", ifName, "inet6", "add", subnet.toCIDRString());
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void removeSubnet(String ifName, Tun.Subnet subnet) throws IOException {
		try {
			if (subnet.isIPv4())
				TunInterfaceConfigurer.runCommand("ifconfig", ifName, "inet", subnet.toCIDRString(), subnet.address().getHostAddress(), "-alias");
			else
				TunInterfaceConfigurer.runCommand("ifconfig", ifName, "inet6", "delete", subnet.address().getHostAddress());
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void up(String ifName) throws IOException {
		try {
			TunInterfaceConfigurer.runCommand("ifconfig", ifName, "up");
		} catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

	@Override
	public Set<Tun.Subnet> subnets(String ifName) throws IOException {
		try {
			return TunInterfaceConfigurer.runCommand("ifconfig", ifName).lines()
				.map(String::strip)
				.filter(s -> s.startsWith("inet"))
				.map(this::parseIpconfigLine)
				.collect(Collectors.toSet());
		} catch (InterruptedException e) {
			throw new IOException(e);
		}
	}

	private Tun.Subnet parseIpconfigLine(String line) {
		if (line.startsWith("inet6"))
			return parseIpconfigLineIPv6(line);
		else
			return parseIpconfigLineIPv4(line);
	}

	private Tun.Subnet parseIpconfigLineIPv4(String line) {
		try {
			var parts = line.split(" ");
			var address = parts[1];

			int netmask;
			if (parts[2].equals("-->")) // weird tunnel syntax
				netmask = Integer.parseUnsignedInt(parts[5].substring(2), 16);
			else
				netmask = Integer.parseUnsignedInt(parts[3].substring(2), 16);

			// convert netmask hex to inet address
			var netmaskBytes = new byte[4];
			ByteBuffer.wrap(netmaskBytes).putInt(netmask);

			var prefixLength = convertNetmaskToCIDR(InetAddress.getByAddress(netmaskBytes));
			return new Tun.Subnet(InetAddress.getByName(address), prefixLength);
		} catch (UnknownHostException e) {
			throw new IllegalArgumentException("Could not parse ifconfig output", e);
		}
	}

	private Tun.Subnet parseIpconfigLineIPv6(String line) {
		try {
			var parts = line.split(" ");
			var address = parts[1];
			var prefixLength = Integer.parseInt(parts[3]);
			return new Tun.Subnet(InetAddress.getByName(address), prefixLength);
		} catch (UnknownHostException e) {
			throw new IllegalArgumentException("Could not parse ifconfig output", e);
		}
	}
}
