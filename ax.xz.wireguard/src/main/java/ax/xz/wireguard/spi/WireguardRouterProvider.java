package ax.xz.wireguard.spi;

import java.util.ServiceLoader;
import java.util.function.Supplier;

public interface WireguardRouterProvider {
	static WireguardRouterProvider provider() {
		return ServiceLoader.load(WireguardRouterProvider.class).stream()
			.map(Supplier::get).filter(WireguardRouterProvider::isAvailable).findFirst().orElseThrow();
	}

	boolean isAvailable();

	/**
	 * Creates a new WireguardRouter instance.
	 * @return
	 */
	WireguardRouter create();
}
