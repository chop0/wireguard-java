module ax.xz.wireguard {
	requires ax.xz.raw;

	exports ax.xz.wireguard.cli;
	exports ax.xz.wireguard.device;

	exports ax.xz.wireguard.util;
	exports ax.xz.wireguard.device.peer;

	exports ax.xz.wireguard.spi;
	exports ax.xz.wireguard.device.message;
	exports ax.xz.wireguard.device.message.initiation;

	requires transitive ax.xz.wireguard.noise;
	requires jsr305;

	uses ax.xz.wireguard.spi.WireguardRouterProvider;
}
