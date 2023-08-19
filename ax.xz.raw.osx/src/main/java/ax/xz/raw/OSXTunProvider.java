package ax.xz.raw;

import ax.xz.raw.spi.Tun;
import ax.xz.raw.spi.TunProvider;

import java.io.IOException;
import java.lang.foreign.Arena;

import static ax.xz.raw.OSXSyscalls.*;

public class OSXTunProvider implements TunProvider {
	private static final int DEFAULT_MTU = 1500;

	private static final int UTUN_CONTROL_ID;

	static {
		try {
			UTUN_CONTROL_ID = getControlID("com.apple.net.utun_control");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public Tun open() throws IOException {
		requireAvailable();

		try (var arena = Arena.ofConfined()) {
			var addr = sockaddr_ctl.allocate(arena);

			addr.setScId(UTUN_CONTROL_ID);
			addr.setScLen((int) addr.getSeg().byteSize());
			addr.setScFamily(AF_SYSTEM);
			addr.setSsSysaddr(AF_SYS_CONTROL);

			int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

			for (int i = 0; i < 255; i++) {
				addr.setScUnit(i + 1);

				try {
					connect(fd, addr.getSeg());
				} catch (IOException e) {
					continue;
				}

				var result = new OSXUtun(fd, i);
				result.setMTU(DEFAULT_MTU);
				return result;
			}

			throw new IOException("connect: " + strerror(errno()));
		}
	}

	@Override
	public boolean isAvailable() {
		return System.getProperty("os.name").equals("Mac OS X");
	}

	private void requireAvailable() {
		if (!isAvailable())
			throw new IllegalStateException("OS %s not supported".formatted(System.getProperty("os.name")));
	}
}
