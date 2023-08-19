package ax.xz.raw;

import ax.xz.raw.spi.Tun;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.net.Inet4Address;
import java.nio.ByteBuffer;

import static ax.xz.raw.OSXSyscalls.*;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.ValueLayout.*;

class OSXUtun implements Tun {
	/**
	 * struct sockaddr_in {
	 * __uint8_t       sin_len;
	 * sa_family_t     sin_family;
	 * in_port_t       sin_port;
	 * struct  in_addr sin_addr;
	 * char            sin_zero[8];
	 * };
	 */
	private static final MemoryLayout sockaddr_in = MemoryLayout.structLayout(
			JAVA_BYTE.withName("sin_len"),
			JAVA_BYTE.withName("sin_family"),
			JAVA_SHORT.withName("sin_port"),
			MemoryLayout.sequenceLayout(4, JAVA_BYTE).withName("sin_addr"),
			MemoryLayout.sequenceLayout(8, JAVA_BYTE).withName("sin_zero")
	);
	private static final VarHandle sin_len$VH = sockaddr_in.varHandle(groupElement("sin_len"));
	private static final VarHandle sin_family$VH = sockaddr_in.varHandle(groupElement("sin_family"));
	private static final VarHandle sin_port$VH = sockaddr_in.varHandle(groupElement("sin_port"));
	private static final MethodHandle sin_addr$VH = sockaddr_in.sliceHandle(groupElement("sin_addr"));

	/**
	 * struct sockaddr_in6 {
	 * __uint8_t       sin6_len;
	 * sa_family_t     sin6_family;
	 * in_port_t       sin6_port;
	 * __uint32_t      sin6_flowinfo;
	 * struct in6_addr sin6_addr;
	 * __uint32_t      sin6_scope_id;
	 * };
	 */
	private static final MemoryLayout sockaddr_in6 = MemoryLayout.structLayout(
			JAVA_BYTE.withName("sin6_len"),
			JAVA_BYTE.withName("sin6_family"),
			JAVA_SHORT.withName("sin6_port"),
			JAVA_INT.withName("sin6_flowinfo"),
			MemoryLayout.sequenceLayout(16, JAVA_BYTE).withName("sin6_addr"),
			JAVA_INT.withName("sin6_scope_id")
	);
	private static final VarHandle sin6_len$VH = sockaddr_in6.varHandle(groupElement("sin6_len"));
	private static final VarHandle sin6_family$VH = sockaddr_in6.varHandle(groupElement("sin6_family"));
	private static final VarHandle sin6_port$VH = sockaddr_in6.varHandle(groupElement("sin6_port"));
	private static final VarHandle sin6_flowinfo$VH = sockaddr_in6.varHandle(groupElement("sin6_flowinfo"));
	private static final MethodHandle sin6_addr$VH = sockaddr_in6.sliceHandle(groupElement("sin6_addr"));
	private static final VarHandle sin6_scope_id$VH = sockaddr_in6.varHandle(groupElement("sin6_scope_id"));


	/**
	 * struct sockaddr {
	 * __uint8_t sa_len;
	 * sa_family_t sa_family;
	 * <p>
	 * <p>
	 * <p>
	 * char sa_data[14];
	 * <p>
	 * };
	 */
	private static final MemoryLayout sockaddr = MemoryLayout.structLayout(
			JAVA_BYTE.withName("sa_len"),
			JAVA_BYTE.withName("sa_family"),
			MemoryLayout.sequenceLayout(14, JAVA_BYTE).withName("sa_data")
	);

	/**
	 * struct ifreq {
	 * char ifr_name[16];
	 * union {
	 * struct sockaddr ifru_addr;
	 * struct sockaddr ifru_dstaddr;
	 * struct sockaddr ifru_broadaddr;
	 * short ifru_flags;
	 * int ifru_metric;
	 * int ifru_mtu;
	 * int ifru_phys;
	 * int ifru_media;
	 * int ifru_intval;
	 * caddr_t ifru_data;
	 * struct ifdevmtu ifru_devmtu;
	 * struct ifkpi ifru_kpi;
	 * u_int32_t ifru_wake_flags;
	 * u_int32_t ifru_route_refcnt;
	 * int ifru_cap[2];
	 * u_int32_t ifru_functional_type;
	 * # 325 "net/if.h"
	 * } ifr_ifru;
	 */
	private static final MemoryLayout ifreq = MemoryLayout.structLayout(
			MemoryLayout.sequenceLayout(16, C_CHAR).withName("ifr_name"),
			MemoryLayout.unionLayout(
					sockaddr_in6.withName("ifru_addr6"),
					sockaddr.withName("ifru_addr"),
					sockaddr.withName("ifru_dstaddr"),
					sockaddr.withName("ifru_broadaddr"),

					JAVA_SHORT.withName("ifru_flags"),
					JAVA_INT.withName("ifru_metric"),
					JAVA_INT.withName("ifru_mtu"),
					JAVA_INT.withName("ifru_phys"),
					JAVA_INT.withName("ifru_media"),
					JAVA_INT.withName("ifru_intval"),

					C_POINTER.withName("ifru_data"),

					JAVA_INT.withName("ifru_wake_flags"),
					JAVA_INT.withName("ifru_route_refcnt"),

					MemoryLayout.sequenceLayout(2, JAVA_INT).withName("ifru_cap"),
					JAVA_INT.withName("ifru_functional_type")
			).withName("ifr_ifru"),
			JAVA_INT.withName("ifr6_prefixlen"),
			JAVA_INT.withName("ifr6_ifindex")
	);
	private static final MethodHandle ifr_name$VH = ifreq.sliceHandle(groupElement("ifr_name"));
	private static final VarHandle mtu$VH = ifreq.varHandle(groupElement("ifr_ifru"), groupElement("ifru_mtu"));
	private static final MethodHandle ifru_addr$VH = ifreq.sliceHandle(groupElement("ifr_ifru"), groupElement("ifru_addr"));
	private static final MethodHandle ifru_addr6$VH = ifreq.sliceHandle(groupElement("ifr_ifru"), groupElement("ifru_addr6"));
	private static final MethodHandle ifr6_prefixlen$VH = ifreq.sliceHandle(groupElement("ifr6_prefixlen"));
	private static final MethodHandle ifr6_ifindex$VH = ifreq.sliceHandle(groupElement("ifr6_ifindex"));

	private static final long SIOCSIFMTU = 0x80206934L, SIOCSIFADDR = 0x8020690cL, SIOCDIFADDR = 0x80206919L, SIOGIFINDEX = 0x8020691aL;

	private final int fd, tunNumber;
	private int mtu;

	OSXUtun(int fd, int tunNumber) {
		this.fd = fd;
		this.tunNumber = tunNumber;
	}

	@Override
	public void write(ByteBuffer buffer) throws IOException { // TODO:  unit test
		ByteBuffer outBuffer;
		if (!buffer.isDirect()) {
			outBuffer = ByteBuffer.allocateDirect(buffer.remaining());
			outBuffer.put(buffer);
			outBuffer.flip();
		}
		else
			outBuffer = buffer;

		OSXSyscalls.writev(fd, getPacketFamily(outBuffer), outBuffer);
	}

	@Override
	public void read(ByteBuffer buffer) throws IOException {
		ByteBuffer inBuffer;
		if (!buffer.isDirect())
			inBuffer = ByteBuffer.allocateDirect(buffer.remaining());
		else
			inBuffer = buffer;

		interface TempHolder {
			ThreadLocal<ByteBuffer> PACKET_FAMILY = ThreadLocal.withInitial(() ->  ByteBuffer.allocateDirect(4));
		}
		OSXSyscalls.readv(fd, TempHolder.PACKET_FAMILY.get().clear(), inBuffer);

		if (!buffer.isDirect()) {
			inBuffer.flip();
			buffer.put(inBuffer);
		}
	}

	private static ByteBuffer getPacketFamily(ByteBuffer packet) throws IOException {
		interface Holder {
			ByteBuffer IPV4 = ByteBuffer.allocateDirect(4).putInt(AF_INET).flip();
			ByteBuffer IPV6 = ByteBuffer.allocateDirect(4).putInt(AF_INET6).flip();
		}

		return switch (packet.get(packet.position()) >> 4) {
			case 4 -> Holder.IPV4.duplicate();
			case 6 -> Holder.IPV6.duplicate();
			default -> throw new IOException("Unknown IP version");
		};
	}

	@Override
	public void setMTU(int mtu) throws IOException {
		int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

		try (var arena = Arena.ofConfined()) {
			var ifr = arena.allocate(ifreq);
			((MemorySegment) ifr_name$VH.invokeExact(ifr)).setUtf8String(0, name());
			mtu$VH.set(ifr, mtu);

			ioctl(sockfd, SIOCSIFMTU, ifr);
			this.mtu = mtu;
		} catch (Throwable e) {
			throw new Error(e);
		} finally {
			OSXSyscalls.close(sockfd);
		}
	}

	@Override
	public int mtu() {
		return mtu;
	}

	public String name() {
		return "utun" + tunNumber;
	}

	@Override
	public void close() throws IOException {
		OSXSyscalls.close(fd);
	}

	@Override
	public void addSubnet(Subnet subnet) throws IOException {
		try {
			if (subnet.isIPv4())
				runCommand("ifconfig", name(), "inet", subnet.toCIDRString(), subnet.address().getHostAddress(), "alias");
			else
				runCommand("ifconfig", name(), "inet6", subnet.toCIDRString(), "alias");
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void removeSubnet(Subnet subnet) throws IOException {
		try {
			if (subnet.isIPv4())
				runCommand("ifconfig", name(), "inet", subnet.toCIDRString(), subnet.address().getHostAddress(), "-alias");
			else
				runCommand("ifconfig", name(), "inet6", subnet.toCIDRString(), "-alias");
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	private MemorySegment getAddressIoctl(Subnet subnet, Arena arena) throws Throwable {
		MemorySegment addr;

		if (subnet.address() instanceof Inet4Address) {
			addr = arena.allocate(sockaddr_in);
			sin_len$VH.set(addr, (byte) sockaddr_in.byteSize());
			sin_family$VH.set(addr, (byte) AF_INET);
			sin_port$VH.set(addr, (short) 0);
			((MemorySegment) sin_addr$VH.invokeExact(addr)).copyFrom(MemorySegment.ofArray(subnet.address().getAddress()));
		} else {
			addr = arena.allocate(sockaddr_in6);
			sin6_len$VH.set(addr, (byte) sockaddr_in6.byteSize());
			sin6_family$VH.set(addr, (byte) AF_INET6);
			sin6_port$VH.set(addr, (short) 0);
			sin6_flowinfo$VH.set(addr, 0);
			((MemorySegment) sin6_addr$VH.invokeExact(addr)).copyFrom(MemorySegment.ofArray(subnet.address().getAddress()));
		}

		var ifr = arena.allocate(ifreq);
		((MemorySegment) ifr_name$VH.invokeExact(ifr)).setUtf8String(0, name());
		((MemorySegment) ifru_addr$VH.invokeExact(ifr)).reinterpret(addr.byteSize()).copyFrom(addr);

		return ifr;
	}

	public static String runCommand(String... command) throws IOException, InterruptedException {
		var pb = new ProcessBuilder();
		pb.command(command);

		System.out.println("> " + String.join(" ", command));

		var process = pb.start();

		if (process.waitFor() != 0) {
			var result = new String(process.getInputStream().readAllBytes());
			System.err.print(result);
			System.err.flush();
			throw new IOException();
		}
		var result = new String(process.getInputStream().readAllBytes());

		System.out.print(result);
		System.out.flush();
		return result;
	}
}
