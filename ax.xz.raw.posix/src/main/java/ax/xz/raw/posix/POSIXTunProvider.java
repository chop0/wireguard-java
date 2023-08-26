package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;
import ax.xz.raw.spi.TunProvider;

import java.io.IOException;

public class POSIXTunProvider implements TunProvider {
	private static final String LIBRARY_NAME = "posix_raw";
	private static final boolean isAvailable;

	static {
		boolean loadSuccess;
		try {
			System.loadLibrary(LIBRARY_NAME);
			loadSuccess = true;
		} catch (UnsatisfiedLinkError e) {
			loadSuccess = false;
		}

		isAvailable = loadSuccess;
	}

	@Override
	public native Tun open() throws IOException;

	@Override
	public boolean isAvailable() {
		return isAvailable;
	}
}
