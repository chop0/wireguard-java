package ax.xz.raw.posix.osx;

import ax.xz.raw.posix.TunInterfaceConfigurer;
import ax.xz.raw.posix.osx.gen.*;
import ax.xz.raw.spi.Tun;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Set;
import java.util.stream.Collectors;

import static ax.xz.raw.posix.gen.posix_tun_h.C_INT;
import static ax.xz.raw.posix.gen.posix_tun_h.C_POINTER;
import static ax.xz.raw.posix.osx.gen.osx_tun_h.*;
import static ax.xz.raw.posix.gen.posix_tun_h.*;
import static ax.xz.raw.spi.Tun.Subnet.convertNetmaskToCIDR;
import static java.nio.ByteOrder.LITTLE_ENDIAN;

/**
 * Adds and removes subnets from an interface using the ip command.
 */
public class OSXInterfaceConfigurer implements TunInterfaceConfigurer {
	private static final ioctl ioctlAliasreq = ioctl.makeInvoker(C_POINTER.withTargetLayout(ifaliasreq.layout()));
	private static final ioctl ioctlAliasreq6 = ioctl.makeInvoker(C_POINTER.withTargetLayout(in6_aliasreq.layout()));

	@Override
	public void addSubnet(String ifName, Tun.Subnet subnet) throws IOException {
		add_inet(ifName, subnet);
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

	public static void add_inet(String ifName, Tun.Subnet subnet) throws IOException {
		boolean isIPv4 = subnet.isIPv4();
		var family = isIPv4 ? AF_INET() : AF_INET6();
		var requestLayout = isIPv4 ? ifaliasreq.layout() : in6_aliasreq.layout();

		try (var allocator = Arena.ofConfined()) {
			int sockfd = socket(family, SOCK_DGRAM(), 0);
			if (sockfd == -1) {
				terror("socket");
			}

			var aliasreq = allocator.allocate(requestLayout);
			var sin = makeSockaddr(allocator, subnet.address().getAddress());
			var netmask = makeSockaddr(allocator, makeCIDRNetmask(isIPv4, subnet.prefixLength()));

			if (isIPv4) {
				ifaliasreq.ifra_name(aliasreq).setUtf8String(0, ifName);
				ifaliasreq.ifra_addr(aliasreq).copyFrom(sin);
				ifaliasreq.ifra_broadaddr(aliasreq).copyFrom(sin);
				ifaliasreq.ifra_mask(aliasreq).copyFrom(netmask);
			} else {
				in6_aliasreq.ifra_name(aliasreq).setUtf8String(0, ifName);
				in6_aliasreq.ifra_addr(aliasreq).copyFrom(sin);
				in6_aliasreq.ifra_prefixmask(aliasreq).copyFrom(netmask);
				in6_aliasreq.ifra_lifetime(aliasreq).fill((byte) 0xff);
			}

			if (isIPv4) {
				if (ioctlAliasreq.apply(sockfd, SIOCAIFADDR(), aliasreq) < 0) {
					terror("ioctl(SIOCAIFADDR)");
				}
			}
			else {
				if (ioctlAliasreq6.apply(sockfd, SIOCAIFADDR_IN6(), aliasreq) < 0) {
					terror("ioctl(SIOCAIFADDR_IN6)");
				}
			}
		} catch (IOException t) {
			throw t;
		} catch (Throwable t) {
			throw new RuntimeException(t);
		}
	}

	private static MemorySegment makeSockaddr(SegmentAllocator allocator, byte[] address) {
		return switch (address.length) {
			case 16 -> {
				var sin = sockaddr_in6.allocate(allocator);

				sockaddr_in6.sin6_family(sin, (byte) AF_INET6());
				in6_addr.__u6_addr(sockaddr_in6.sin6_addr(sin)).copyFrom(MemorySegment.ofArray(address));
				sockaddr_in6.sin6_len(sin, (byte) sin.byteSize());

				yield sin;
			}
			case 4 -> {
				int addressBytes = ByteBuffer.wrap(address).order(LITTLE_ENDIAN).getInt();
				var sin = sockaddr_in.allocate(allocator);

				sockaddr_in.sin_family(sin, (byte) AF_INET());
				in_addr.s_addr(sockaddr_in.sin_addr(sin), addressBytes);
				sockaddr_in.sin_len(sin, (byte) sin.byteSize());

				yield sin;
			}
			default -> throw new IllegalArgumentException("Invalid address length");
		};
	}

	private static byte[] makeCIDRNetmask(boolean isIpv4, int prefixLength) {
		byte[] netmask = new byte[isIpv4 ? 4 : 16];
		// set prefixLength bits to 1
		for (int i = 0; i < prefixLength; i++) {
			int byteIndex = i / 8;
			int bitIndex = i % 8;

			netmask[byteIndex] |= (byte) (1 << (7 - bitIndex));
		}
		return netmask;
	}

	private static void terror(String step) throws IOException {
		throw new IOException(STR."\{step}: \{strerror(__error().get(C_INT, 0)).getUtf8String(0)}");
	}
}
