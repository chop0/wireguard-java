import ax.xz.raw.posix.POSIXTunProvider;
import ax.xz.raw.spi.TunProvider;

module ax.xz.raw {
	exports ax.xz.raw.spi;

	uses ax.xz.raw.spi.TunProvider;
	provides TunProvider with POSIXTunProvider;
}
