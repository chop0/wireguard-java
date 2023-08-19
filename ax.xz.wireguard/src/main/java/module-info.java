module ax.xz.wireguard {
	requires org.slf4j;

	requires ax.xz.raw;

	exports ax.xz.wireguard.cli;
	exports ax.xz.wireguard.device;

	requires ax.xz.wireguard.noise;
}
