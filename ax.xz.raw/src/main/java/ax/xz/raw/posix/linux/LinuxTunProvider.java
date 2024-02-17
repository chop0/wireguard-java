package ax.xz.raw.posix.linux;

import ax.xz.raw.posix.POSIXTun;
import ax.xz.raw.posix.gen.posix_tun_h;
import ax.xz.raw.posix.linux.gen.ifreq;
import ax.xz.raw.spi.Tun;
import ax.xz.raw.spi.TunProvider;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

import static ax.xz.raw.posix.gen.posix_tun_h.C_INT;
import static ax.xz.raw.posix.linux.gen.linux_tun_h.*;
import static ax.xz.raw.posix.gen.posix_tun_h.*;

public class LinuxTunProvider implements TunProvider {
	private static final ioctl ifreq_ioctl = ioctl.makeInvoker(posix_tun_h.C_POINTER.withTargetLayout(ifreq.layout()));
	private static final open open_flags = open.makeInvoker();

	private static final VarHandle FD_HANDLE;

	static {
		try {
			FD_HANDLE = MethodHandles.privateLookupIn(FileDescriptor.class, MethodHandles.lookup()).findVarHandle(FileDescriptor.class, "fd", int.class);
		} catch (IllegalAccessException e) {
			throw new ExceptionInInitializerError(e);
		} catch (NoSuchFieldException e) {
			throw new AssertionError(e);
		}
	}


	@Override
	public Tun open() throws IOException {
		try (var allocator = Arena.ofConfined()) {
			int fd = open_flags.apply(allocator.allocateUtf8String("/dev/net/tun"), O_RDWR());
			if (fd < 0) {
				terror("open");
			}

			var ifr = ifreq.allocate(allocator);
			ifreq.ifr_ifru.ifru_flags(ifreq.ifr_ifru(ifr), (short) (IFF_TUN() | IFF_NO_PI()));
			int err = ifreq_ioctl.apply(fd, TUNSETIFF(), ifr);
			if (err < 0) {
				close(fd);
				terror("TUNSETIFF");
			}

			var fdObj = new FileDescriptor();
			FD_HANDLE.set(fdObj, fd);

			return new POSIXTun(fdObj, ifreq.ifr_ifrn.ifrn_name(ifreq.ifr_ifrn(ifr)).getUtf8String(0));
		}
	}

	@Override
	public boolean isAvailable() {
		return System.getProperty("os.name").equals("Linux");
	}

	private static void terror(String step) throws IOException {
		throw new IOException(STR."\{step}: \{strerror(__errno_location().get(C_INT, 0)).getUtf8String(0)}");
	}
}
