module ax.xz.wireguard.noise {
	exports ax.xz.wireguard.noise.handshake;
	exports ax.xz.wireguard.noise.keys;
	exports ax.xz.wireguard.noise.crypto to ax.xz.wireguard;

	requires jdk.incubator.vector;
}