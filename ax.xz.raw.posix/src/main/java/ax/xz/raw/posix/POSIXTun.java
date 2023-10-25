package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;
import jdk.nio.Channels;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Arrays;
import java.util.Set;

import static ax.xz.raw.posix.POSIXTunUtils.getPacketFamily;
import static java.lang.System.Logger.Level.INFO;
import static java.util.Objects.requireNonNull;

public class POSIXTun implements Tun {
	private static final boolean needsAfTypePrefix = System.getProperty("os.name").toLowerCase().contains("bsd") || System.getProperty("os.name").toLowerCase().contains("os x");

	private static final VarHandle STATE;

	static {
		try {
			STATE = MethodHandles.lookup().findVarHandle(POSIXTun.class, "state", State.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private static final System.Logger logger = System.getLogger(POSIXTun.class.getSimpleName());

	private final String name;

	private final FileDescriptor[] fileDescriptors;
	private final FileChannel[] inputChannels;
	private final FileChannel[] outputChannels;
	private final SelectableChannel[] selectableChannels;
	private final Selector readSelector, writeSelector;


	private volatile State state = State.DOWN;

	private POSIXTun(FileDescriptor[] fds, String name) {
		for (var fd : fds)
			if (!fd.valid())
				throw new IllegalArgumentException("Invalid file descriptor");

		this.fileDescriptors = fds;
		this.name = requireNonNull(name, "name must not be null");

		this.inputChannels = new FileChannel[fileDescriptors.length];
		this.outputChannels = new FileChannel[fileDescriptors.length];
		this.selectableChannels = new SelectableChannel[fileDescriptors.length];

		for (int i = 0; i < fileDescriptors.length; i++) {
			var fd = fileDescriptors[i];

			inputChannels[i] = new FileInputStream(fd).getChannel();
			outputChannels[i] = new FileOutputStream(fd).getChannel();
			selectableChannels[i] = Channels.readWriteSelectableChannel(fd, new Channels.SelectableChannelCloser() {
				@Override
				public void implCloseChannel(SelectableChannel sc) throws IOException {
					new FileOutputStream(fd).close();
				}

				@Override
				public void implReleaseChannel(SelectableChannel sc) {

				}
			});
		}

		try {
			this.readSelector = Selector.open();
			this.writeSelector = Selector.open();

			for (int i = 0; i < selectableChannels.length; i++) {
				selectableChannels[i].configureBlocking(false);
				selectableChannels[i].register(readSelector, SelectionKey.OP_READ, new ChannelPair(inputChannels[i], outputChannels[i]));
				selectableChannels[i].register(writeSelector, SelectionKey.OP_WRITE, new ChannelPair(inputChannels[i], outputChannels[i]));
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		}

		logger.log(INFO, "Opened tun {0} with file descriptors {1}", name, Arrays.toString(fileDescriptors));
	}

	@Override
	public int write(ByteBuffer buffer) throws IOException {
		requireOpen();

		SelectionKey key;
		for (;;) {
//			outer:
//			for (; ; ) {
//				writeSelector.select();
//
//				synchronized (writeSelector) {
//					for (var iter = writeSelector.selectedKeys().iterator(); iter.hasNext(); ) {
//						if ((key = iter.next()) != null && key.isWritable()) {
//							iter.remove();
//							break outer;
//						}
//					}
//				}
//			}

			var outputChannel = outputChannels[0];
			int bytesWritten;
			if (needsAfTypePrefix)
				bytesWritten = (int) (outputChannel.write(new ByteBuffer[]{getPacketFamily(buffer), buffer}) - 4);
			else
				bytesWritten = outputChannel.write(buffer);

			if (bytesWritten > 0)
				return bytesWritten;
		}
	}

	@Override
	public int read(ByteBuffer buffer) throws IOException {
		interface TempHolder {
			ThreadLocal<ByteBuffer> PACKET_FAMILY = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(4));
		}

		requireOpen();

		SelectionKey key;
		for (;;) {
			outer:
			for (; ; ) {
				readSelector.select();

				synchronized (readSelector) {
					for (var iter = readSelector.selectedKeys().iterator(); iter.hasNext(); ) {
						if ((key = iter.next()) != null && key.isReadable()) {
							iter.remove();
							break outer;
						}
					}
				}
			}

			var inputChannel = ((ChannelPair) key.attachment()).input;

			int bytesRead;
			if (needsAfTypePrefix)
				bytesRead = (int) (inputChannel.read(new ByteBuffer[]{TempHolder.PACKET_FAMILY.get().clear(), buffer}) - 4);
			else
				bytesRead = inputChannel.read(buffer);

			if (bytesRead > 0)
				return bytesRead;
		}
	}


	@Override
	public void close() throws IOException {
		if (!(STATE.compareAndSet(this, State.UP, State.CLOSED) || STATE.compareAndSet(this, State.DOWN, State.CLOSED)))
			return;

		for (int i = 0; i < fileDescriptors.length; i++) {
			inputChannels[i].close();
			outputChannels[i].close();
		}
	}

	@Override
	public void addSubnet(Subnet subnet) throws IOException {
		TunInterfaceConfigurer.get().addSubnet(name(), subnet);
		if (STATE.compareAndSet(this, State.DOWN, State.UP)) {
			TunInterfaceConfigurer.get().up(name());
		}
	}

	@Override
	public void removeSubnet(Subnet subnet) throws IOException {
		TunInterfaceConfigurer.get().removeSubnet(name(), subnet);
	}

	@Override
	public Set<Subnet> subnets() throws IOException {
		return TunInterfaceConfigurer.get().subnets(name());
	}

	@Override
	public native void setMTU(int mtu) throws IOException;

	@Override
	public native int mtu() throws IOException;

	private void requireOpen() {
		if (!isOpen())
			throw new IllegalStateException("Tun is not up");
	}

	@Override
	public boolean isOpen() {
		return state == State.UP;
	}

	public String name() {
		return name;
	}

	@Override
	public String toString() {
		return name();
	}

	enum State {
		DOWN, UP, CLOSED
	}

	record ChannelPair(FileChannel input, FileChannel output) {}
}
