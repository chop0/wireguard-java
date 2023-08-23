module ax.xz.wireguard {
	requires ax.xz.raw;

	exports ax.xz.wireguard.cli;
	exports ax.xz.wireguard.device;

	opens ax.xz.wireguard.device.peer to ax.xz.logging;

	requires ax.xz.wireguard.noise;
}
