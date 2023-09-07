import ax.xz.raw.posix.POSIXTunProvider;
import ax.xz.raw.spi.TunProvider;

module ax.xz.raw.posix {
	requires ax.xz.raw;
	requires jsr305;

	exports ax.xz.raw.posix;
	provides TunProvider with POSIXTunProvider;
}
