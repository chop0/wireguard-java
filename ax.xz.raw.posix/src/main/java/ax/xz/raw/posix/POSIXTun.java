package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Arrays;
import java.util.Set;

import static ax.xz.raw.posix.POSIXTunUtils.getPacketFamily;
import static java.lang.System.Logger.Level.INFO;
import static java.util.Objects.requireNonNull;

public class POSIXTun implements Tun {
	private static final boolean needsAfTypePrefix = System.getProperty("os.name").toLowerCase().contains("bsd") || System.getProperty("os.name").toLowerCase().contains("os x");

	private static final VarHandle FILE_DESCRIPTOR_READ_INDEX;
	private static final VarHandle FILE_DESCRIPTOR_WRITE_INDEX;

	private static final VarHandle STATE;

	static {
		try {
			FILE_DESCRIPTOR_READ_INDEX = MethodHandles.lookup().findVarHandle(POSIXTun.class, "readFdIndex", int.class);
			FILE_DESCRIPTOR_WRITE_INDEX = MethodHandles.lookup().findVarHandle(POSIXTun.class, "writeFdIndex", int.class);

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

	private volatile int readFdIndex = 0;
	private volatile int writeFdIndex = 0;

	private volatile State state = State.DOWN;

	private POSIXTun(FileDescriptor[] fds, String name) {
		for (var fd : fds)
			if (!fd.valid())
				throw new IllegalArgumentException("Invalid file descriptor");

		this.fileDescriptors = fds;
		this.name = requireNonNull(name, "name must not be null");


		this.inputChannels = new FileChannel[fileDescriptors.length];
		this.outputChannels = new FileChannel[fileDescriptors.length];

		for (int i = 0; i < fileDescriptors.length; i++) {
			inputChannels[i] = new FileInputStream(fileDescriptors[i]).getChannel();
			outputChannels[i] = new FileOutputStream(fileDescriptors[i]).getChannel();
		}

		logger.log(INFO, "Opened tun {0} with file descriptors {1}", name, Arrays.toString(fileDescriptors));
	}

	@Override
	public int write(ByteBuffer buffer) throws IOException {
		requireOpen();

		int fdIndex = rotateFdIndex(FILE_DESCRIPTOR_WRITE_INDEX);
		var outputChannel = outputChannels[fdIndex];

		if (needsAfTypePrefix)
			return (int) (outputChannel.write(new ByteBuffer[]{getPacketFamily(buffer), buffer}) - 4);
		else
			return outputChannel.write(buffer);
	}

	@Override
	public int read(ByteBuffer buffer) throws IOException {
		interface TempHolder {
			ThreadLocal<ByteBuffer> PACKET_FAMILY = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(4));
		}

		requireOpen();

		int fdIndex = rotateFdIndex(FILE_DESCRIPTOR_READ_INDEX);
		var inputChannel = inputChannels[fdIndex];

		if (needsAfTypePrefix)
			return (int) (inputChannel.read(new ByteBuffer[]{TempHolder.PACKET_FAMILY.get().clear(), buffer}) - 4);
		else
			return inputChannel.read(buffer);
	}

	private int rotateFdIndex(VarHandle vh) {
		return (int) (Integer.toUnsignedLong((int) vh.getAndAdd(this, 1)) % fileDescriptors.length);
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
}
