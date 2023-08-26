package ax.xz.raw.spi;

import java.io.IOException;
import java.util.ServiceLoader;

/**
 * A provider for raw sockets.  A raw socket can send and receive L3 packets.
 */
public interface RawSocketProvider {
	static RawSocketProvider getProvider() {
		return ServiceLoader.load(RawSocketProvider.class).stream().map(ServiceLoader.Provider::get)
				.filter(RawSocketProvider::isAvailable)
				.findFirst().orElseThrow(() -> new IllegalStateException("No RawSocketProvider found"));
	}

	/**
	 * Opens a new raw socket;  typically, this will face the internet or a local network.
	 * @return a new raw socket
	 * @throws IOException if an I/O error occurs
	 * @throws IllegalStateException if the provider is not available
	 */
	RawSocket open() throws IOException;

	/**
	 * Checks if the provider is available
	 * @return true if the provider is available (i.e. the OS is supported)
	 */
	boolean isAvailable();
}
