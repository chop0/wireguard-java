package ax.xz.raw.spi;

import java.io.IOException;
import java.util.ServiceLoader;


public interface BatchedDatagramSocketProvider {
	static BatchedDatagramSocketProvider getProvider() {
		return ServiceLoader.load(BatchedDatagramSocketProvider.class, ClassLoader.getSystemClassLoader()).stream().map(ServiceLoader.Provider::get)
				.filter(BatchedDatagramSocketProvider::isAvailable)
				.findFirst().orElseThrow(() -> new IllegalStateException("No BatchedDatagramSocketProvider found"));
	}

	BatchedDatagramSocket open() throws IOException;

	/**
	 * Checks if the provider is available
	 * @return true if the provider is available (i.e. the OS is supported)
	 */
	boolean isAvailable();
}
