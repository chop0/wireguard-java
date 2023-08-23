module ax.xz.wireguard.noise {
	requires org.bouncycastle.provider;

	exports ax.xz.wireguard.noise.handshake;
	exports ax.xz.wireguard.noise.keys;
	exports ax.xz.wireguard.noise.crypto to ax.xz.wireguard;
}
