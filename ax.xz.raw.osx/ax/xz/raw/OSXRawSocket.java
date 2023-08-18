package ax.xz.raw;

import ax.xz.raw.spi.RawSocket;

import java.io.IOException;
import java.nio.ByteBuffer;

class OSXRawSocket implements RawSocket {
	private final int fd;


	OSXRawSocket(int fd) {
		this.fd = fd;
	}

	@Override
	public void write(ByteBuffer buffer) throws IOException {
		OSXSyscalls.write(fd, buffer);
	}

	@Override
	public void read(ByteBuffer buffer) throws IOException {
		OSXSyscalls.read(fd, buffer);
	}

	@Override
	public void setMTU(int mtu) throws IOException {
		// TODO
		throw new UnsupportedOperationException();
	}

	@Override
	public int mtu() {
		// TODO
		throw new UnsupportedOperationException();
	}

	@Override
	public void close() throws IOException {
		OSXSyscalls.close(fd);
	}
}
