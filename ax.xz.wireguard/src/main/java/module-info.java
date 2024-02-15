module ax.xz.wireguard {
	requires ax.xz.raw;

	exports ax.xz.wireguard.cli;
	exports ax.xz.wireguard.device;

	exports ax.xz.wireguard.util;

	requires ax.xz.wireguard.noise;
}
