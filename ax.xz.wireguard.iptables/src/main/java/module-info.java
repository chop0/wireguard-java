module ax.xz.wireguard.iptables {
	requires ax.xz.wireguard;

	provides ax.xz.wireguard.spi.WireguardRouterProvider with ax.xz.wireguard.iptables.IptablesRouterProvider;
}
