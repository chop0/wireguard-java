module ax.xz.wireguard {
	requires java.management;

	requires ax.xz.raw;

	requires org.slf4j;
	requires org.bouncycastle.provider;

	exports ax.xz.wireguard.cli;
	exports ax.xz.wireguard.device;
	exports ax.xz.wireguard.crypto.keys;
}
