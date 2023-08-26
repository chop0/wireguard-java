package ax.xz.raw.posix;

import ax.xz.raw.spi.RawSocket;
import ax.xz.raw.spi.RawSocketProvider;

import java.io.File;
import java.io.IOException;

public class POSIXRawSocketProvider implements RawSocketProvider {
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
	public native RawSocket open() throws IOException;

	@Override
	public boolean isAvailable() {
		return isAvailable;
	}
}
