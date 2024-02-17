package ax.xz.raw.posix;

import ax.xz.raw.posix.linux.LinuxTunProvider;
import ax.xz.raw.posix.osx.OSXTunProvider;
import ax.xz.raw.spi.Tun;
import ax.xz.raw.spi.TunProvider;

import java.io.IOException;

public class POSIXTunProvider implements TunProvider {
	private TunProvider delegate;

	public POSIXTunProvider() {
		if (isBSD())
			delegate = new OSXTunProvider();
		else if (isLinux())
			delegate = new LinuxTunProvider();
		else
			delegate = null;
	}

	@Override
	public Tun open() throws IOException {
		return delegate.open();
	}

	@Override
	public boolean isAvailable() {
		return delegate != null && delegate.isAvailable();
	}

	private static boolean isBSD() {
		var name = System.getProperty("os.name").toLowerCase();
		return name.contains("bsd") || name.contains("os x");
	}

	private static boolean isLinux() {
		return System.getProperty("os.name").toLowerCase().contains("linux");
	}
}
