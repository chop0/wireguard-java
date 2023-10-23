package ax.xz.wireguard.iptables;

import ax.xz.wireguard.spi.WireguardRouter;
import ax.xz.wireguard.spi.WireguardRouterProvider;

import java.io.IOException;

import static ax.xz.wireguard.iptables.CommandUtils.runCommand;

public class IptablesRouterProvider implements WireguardRouterProvider {
	@Override
	public WireguardRouter create() throws IOException {
		return new IptablesRouter();
	}

	public boolean isAvailable() {
		try {
			runCommand("iptables", "--version");
			return true;
		} catch (IOException e) {
			return false;
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return false;
		}
	}

}
