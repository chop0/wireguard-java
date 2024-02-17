package ax.xz.raw.spi;

import java.io.IOException;
import java.util.ServiceLoader;

/**
 * A provider for userspace tun devices.  A tun device is a virtual network interface that can be used to send and receive IP packets, and
 * is represented by a {@link RawSocket} object.
 */
public interface TunProvider {
	static TunProvider getProvider() {
		return ServiceLoader.load(TunProvider.class).stream().map(ServiceLoader.Provider::get)
				.filter(TunProvider::isAvailable)
				.findFirst().orElseThrow(() -> new IllegalStateException("No TunProvider found"));
	}

	/**
	 * Opens a new tun device.  The returned object should be somehow routa
	 * @return a new tun device
	 * @throws IOException if an I/O error occurs
	 * @throws IllegalStateException if the provider is not available
	 */
	Tun open() throws IOException;

	/**
	 * Checks if the provider is available
	 * @return true if the provider is available (i.e. the OS is supported)
	 */
	boolean isAvailable();
}
