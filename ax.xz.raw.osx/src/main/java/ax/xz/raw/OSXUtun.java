package ax.xz.raw;

import ax.xz.raw.spi.Tun;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;

import static ax.xz.raw.OSXSyscalls.*;
import static java.lang.System.Logger.Level.DEBUG;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.ValueLayout.*;

class OSXUtun implements Tun {
	private static final System.Logger logger = System.getLogger(OSXUtun.class.getName());

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

	private static final long SIOCSIFMTU = 0x80206934L;

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
		} else
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
			ThreadLocal<ByteBuffer> PACKET_FAMILY = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(4));
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

	public static void runCommand(String... command) throws IOException, InterruptedException {
		var pb = new ProcessBuilder();
		pb.command(command);

		logger.log(DEBUG, "> " + String.join(" ", command));

		var process = pb.start();

		if (process.waitFor() != 0) {
			var result = new String(process.getInputStream().readAllBytes());
			throw new IOException("Command %s failed with exit code %d:  %s".formatted(String.join(" ", command), process.exitValue(), result));
		}

		var result = new String(process.getInputStream().readAllBytes());
		if (!result.isEmpty())
			logger.log(DEBUG, result);
	}
}
