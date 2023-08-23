module ax.xz.raw.osx {
	requires transitive ax.xz.raw;
	requires jsr305;

	provides ax.xz.raw.spi.TunProvider with ax.xz.raw.OSXTunProvider;
	provides ax.xz.raw.spi.RawSocketProvider with ax.xz.raw.OSXRawSocketProvider;

	exports ax.xz.raw;
}
