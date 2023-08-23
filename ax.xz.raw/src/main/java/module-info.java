module ax.xz.raw {
	requires jsr305;
	exports ax.xz.raw.spi;

	uses ax.xz.raw.spi.TunProvider;
	uses ax.xz.raw.spi.RawSocketProvider;
}
