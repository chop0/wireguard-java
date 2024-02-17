package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Set;

import static ax.xz.raw.posix.osx.gen.osx_tun_h.AF_INET;
import static ax.xz.raw.posix.osx.gen.osx_tun_h.AF_INET6;
import static java.util.Objects.requireNonNull;

public class POSIXTun implements Tun {
	private static final System.Logger logger = System.getLogger(POSIXTun.class.getName());

	private final String name;

	private final FileChannel inputChannel;
	private final FileChannel outputChannel;
	private final FileDescriptor fd;

	private boolean up = false;

	private void requireOpen() {
		if (!fd.valid())
			throw new IllegalStateException("Tun is closed");
	}

	public POSIXTun(FileDescriptor fd, String name) throws IOException {
		if (!fd.valid())
			throw new IllegalArgumentException("Invalid file descriptor");

		this.fd = fd;
		this.name = requireNonNull(name, "name must not be null");

		this.inputChannel = new FileInputStream(fd).getChannel();
		this.outputChannel = new FileOutputStream(fd).getChannel();
	}

	@Override
	public void write(ByteBuffer buffer) throws IOException { // TODO:  unit test
		requireOpen();

		if (needsAfTypePrefix())
			outputChannel.write(new ByteBuffer[]{getPacketFamily(buffer), buffer});
		else
			outputChannel.write(buffer);
	}

	@Override
	public void read(ByteBuffer buffer) throws IOException {
		requireOpen();

		interface TempHolder {
			ThreadLocal<ByteBuffer> PACKET_FAMILY = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(4));
		}

		if (needsAfTypePrefix())
			inputChannel.read(new ByteBuffer[]{TempHolder.PACKET_FAMILY.get().clear(), buffer});
		else
			inputChannel.read(buffer);
	}

	private static ByteBuffer getPacketFamily(ByteBuffer packet) throws IOException {
		interface Holder {
			ByteBuffer IPV4 = ByteBuffer.allocateDirect(4).putInt(AF_INET()).flip();
			ByteBuffer IPV6 = ByteBuffer.allocateDirect(4).putInt(AF_INET6()).flip();
		}

		return switch (packet.get(packet.position()) >> 4) {
			case 4 -> Holder.IPV4.duplicate();
			case 6 -> Holder.IPV6.duplicate();
			default -> throw new IOException("Unknown IP version");
		};
	}

	@Override
	public void setMTU(int mtu) throws IOException {}

	@Override
	public int mtu() throws IOException { return 1500; }

	public String name() {
		return name;
	}

	@Override
	public void close() throws IOException {
		inputChannel.close();
		outputChannel.close();
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

	@Override
	public String toString() {
		return name;
	}
}