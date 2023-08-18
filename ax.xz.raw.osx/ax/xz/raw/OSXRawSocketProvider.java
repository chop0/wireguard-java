package ax.xz.raw;

import ax.xz.raw.spi.RawSocket;
import ax.xz.raw.spi.RawSocketProvider;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static ax.xz.raw.OSXSyscalls.*;

public class OSXRawSocketProvider implements RawSocketProvider {
	@Override
	public RawSocket open() throws IOException {
		requireAvailable();
		int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

		var value = MemorySegment.ofBuffer(ByteBuffer.allocateDirect(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).flip());
		setsockopt(fd, IPPROTO_IP, IP_HDRINCL, value);

		return new OSXRawSocket(fd);
	}

	@Override
	public boolean isAvailable() {
		return System.getProperty("os.name").equals("Mac OS X");
	}

	private void requireAvailable() {
		if (!isAvailable())
			throw new IllegalStateException("OS %s not supported".formatted(System.getProperty("os.name")));
	}

	public static void main(String[] args) throws IOException {
		RawSocketProvider.getProvider().open();
	}
}
