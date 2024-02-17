package ax.xz.raw.posix.osx;

import ax.xz.raw.posix.POSIXTun;
import ax.xz.raw.posix.osx.gen.ctl_info;
import ax.xz.raw.posix.osx.gen.sockaddr_ctl;
import ax.xz.raw.spi.Tun;
import ax.xz.raw.spi.TunProvider;

import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.util.Map;

import static ax.xz.raw.posix.gen.posix_tun_h.*;
import static ax.xz.raw.posix.gen.posix_tun_h.C_POINTER;
import static ax.xz.raw.posix.osx.gen.osx_tun_h.*;

public class OSXTunProvider implements TunProvider {
	private static final ioctl ioctlControlId = ioctl.makeInvoker(C_POINTER.withTargetLayout(ctl_info.layout()));
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
		var fd = OSXTunProvider.open_tun();
		if (fd == null) throw new IOException("Could not open fd");

		var fdObj = new FileDescriptor();
		FD_HANDLE.set(fdObj, (int)fd.getKey());

		return new POSIXTun(fdObj, fd.getValue());
	}

	@Override
	public boolean isAvailable() {
		var name = System.getProperty("os.name").toLowerCase();
		return name.contains("bsd") || name.contains("os x");
	}

	public static Map.Entry<Integer, String> open_tun() {
		try (var allocator = Arena.ofConfined()) {
			int fd = socket(PF_SYSTEM(), SOCK_DGRAM(), SYSPROTO_CONTROL());
			if (fd < 0) {
				return null;
			}

			var addr = sockaddr_ctl.allocate(allocator);
			get_utun_ctl_addr(addr);

			for (int i = 0; i < 255; ++i) {
				sockaddr_ctl.sc_unit(addr, i + 1);
				int err = connect(fd, addr, (int) addr.byteSize());
				if (err < 0) {
					continue;
				}

				return Map.entry(fd, "utun" + i);
			}

			close(fd);
			return null;
		}
	}

	private static int get_control_id(String name) throws IOException {
		int fd = socket(PF_SYSTEM(), SOCK_DGRAM(), SYSPROTO_CONTROL());

		if (fd < 0) {
			throw new IOException("socket: could not get utun control ID");
		}

		try (var allocator = Arena.ofConfined()) {
			var info = ctl_info.allocate(allocator);
			ctl_info.ctl_name(info).setUtf8String(0, name);
			int err = ioctlControlId.apply(fd, CTLIOCGINFO(), info);
			if (err < 0) {
				throw new IOException("ioctl: could not get utun control ID");
			}

			return ctl_info.ctl_id(info);
		} finally {
			close(fd);
		}
	}

	private static void get_utun_ctl_addr(MemorySegment addr) {
		class Holder {
			static final int utun_control_id;

			static {
				try {
					utun_control_id = get_control_id("com.apple.net.utun_control");
				} catch (IOException e) {
					throw new ExceptionInInitializerError(e);
				}
			}
		}

		sockaddr_ctl.sc_len(addr, (byte) sockaddr_ctl.sizeof());
		sockaddr_ctl.sc_family(addr, (byte) AF_SYSTEM());
		sockaddr_ctl.ss_sysaddr(addr, (short) AF_SYS_CONTROL());
		sockaddr_ctl.sc_id(addr, Holder.utun_control_id);
	}
}
