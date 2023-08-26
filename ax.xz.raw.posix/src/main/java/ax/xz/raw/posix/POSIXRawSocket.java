package ax.xz.raw.posix;

import ax.xz.raw.spi.RawSocket;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

class POSIXRawSocket implements RawSocket {
	private final FileChannel inputChannel;
	private final FileChannel outputChannel;

	POSIXRawSocket(FileDescriptor fd) {
		this.inputChannel = new FileInputStream(fd).getChannel();
		this.outputChannel = new FileOutputStream(fd).getChannel();
	}

	@Override
	public void write(ByteBuffer buffer) throws IOException {
		outputChannel.write(buffer);
	}

	@Override
	public void read( ByteBuffer buffer) throws IOException {
		inputChannel.read(buffer);
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
		inputChannel.close();
		outputChannel.close();
	}
}
