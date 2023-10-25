import ax.xz.raw.posix.LinuxBatchedDatagramSocketProvider;
import ax.xz.raw.posix.POSIXTunProvider;
import ax.xz.raw.spi.BatchedDatagramSocketProvider;
import ax.xz.raw.spi.TunProvider;

module ax.xz.raw.posix {
	requires jdk.net;
	requires ax.xz.raw;
	requires jsr305;

	exports ax.xz.raw.posix;
	provides TunProvider with POSIXTunProvider;
	provides BatchedDatagramSocketProvider with LinuxBatchedDatagramSocketProvider;
}
