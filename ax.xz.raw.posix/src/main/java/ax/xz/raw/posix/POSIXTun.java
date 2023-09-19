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

import static java.lang.System.Logger.Level.INFO;
import static java.util.Objects.requireNonNull;

public class POSIXTun implements Tun {
	private static final VarHandle FILE_DESCRIPTOR_READ_INDEX, FILE_DESCRIPTOR_WRITE_INDEX;

	static {
		try {
			FILE_DESCRIPTOR_READ_INDEX = MethodHandles.lookup().findVarHandle(POSIXTun.class, "readFdIndex", int.class);
			FILE_DESCRIPTOR_WRITE_INDEX = MethodHandles.lookup().findVarHandle(POSIXTun.class, "writeFdIndex", int.class);
		} catch (ReflectiveOperationException e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private static final System.Logger logger = System.getLogger(POSIXTun.class.getSimpleName());

	private static final int AF_INET = AFINET();
	private static final int AF_INET6 = AFINET6();

	private final String name;

	private final FileDescriptor[] fileDescriptors;
	private final FileChannel[] inputChannels;
	private final FileChannel[] outputChannels;

	private volatile int readFdIndex = 0;
	private volatile int writeFdIndex = 0;

	private boolean up = false;

	private void requireOpen(FileDescriptor fd) {
		if (!fd.valid())
			throw new IllegalStateException("Tun is closed");
	}

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
	public void write(ByteBuffer buffer) throws IOException {
		int fdIndex = (int)(Integer.toUnsignedLong((int) FILE_DESCRIPTOR_WRITE_INDEX.getAndAdd(this, 1)) % fileDescriptors.length);
		requireOpen(fileDescriptors[fdIndex]);

		if (needsAfTypePrefix())
			outputChannels[fdIndex].write(new ByteBuffer[]{getPacketFamily(buffer), buffer});
		else
			outputChannels[fdIndex].write(buffer);
	}

	@Override
	public void read(ByteBuffer buffer) throws IOException {
		int fdIndex = (int)(Integer.toUnsignedLong((int) FILE_DESCRIPTOR_READ_INDEX.getAndAdd(this, 1)) % fileDescriptors.length);
		requireOpen(fileDescriptors[fdIndex]);

		interface TempHolder {
			ThreadLocal<ByteBuffer> PACKET_FAMILY = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(4));
		}

		if (needsAfTypePrefix())
			inputChannels[fdIndex].read(new ByteBuffer[]{TempHolder.PACKET_FAMILY.get().clear(), buffer});
		else
			inputChannels[fdIndex].read(buffer);
	}

	private static ByteBuffer getPacketFamily(ByteBuffer packet) throws IOException {
		interface Holder {
			ByteBuffer IPV4 = ByteBuffer.allocateDirect(4).putInt(AF_INET).flip();
			ByteBuffer IPV6 = ByteBuffer.allocateDirect(4).putInt(AF_INET6).flip();
		}

		return switch (packet.get(packet.position()) >> 4) {
			case 4 -> Holder.IPV4.duplicate();
			case 6 -> Holder.IPV6.duplicate();
			default -> throw new IOException("Unknown IP version");
		};
	}

	@Override
	public native void setMTU(int mtu) throws IOException;

	@Override
	public native int mtu() throws IOException;

	public String name() {
		return name;
	}

	@Override
	public void close() throws IOException {
		for (int i = 0; i < fileDescriptors.length; i++) {
			inputChannels[i].close();
			outputChannels[i].close();
		}
	}

	@Override
	public void addSubnet(Subnet subnet) throws IOException {
		TunInterfaceConfigurer.get().addSubnet(name(), subnet);
		if (!up) {
			TunInterfaceConfigurer.get().up(name());
			up = true;
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

	private static final boolean needsAfTypePrefix = System.getProperty("os.name").toLowerCase().contains("bsd") || System.getProperty("os.name").toLowerCase().contains("os x");

	private boolean needsAfTypePrefix() {
		return needsAfTypePrefix;
	}

	private static native int AFINET();

	private static native int AFINET6();

	@Override
	public String toString() {
		return name;
	}
}
