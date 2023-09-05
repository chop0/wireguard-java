package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;

import java.io.*;
import java.net.BindException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

import static java.lang.System.Logger.Level.DEBUG;
import static java.util.Objects.requireNonNull;

public class POSIXTun implements Tun {
	private static final System.Logger logger = System.getLogger(POSIXTun.class.getName());

	private static final int AF_INET = AFINET();
	private static final int AF_INET6 = AFINET6();

	private final String name;

	private final FileChannel inputChannel;
	private final FileChannel outputChannel;
	private final FileDescriptor fd;

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
		setMTU(1500);
	}

	@Override
	public void write(ByteBuffer buffer) throws IOException { // TODO:  unit test
		requireOpen();
		outputChannel.write(new ByteBuffer[]{getPacketFamily(buffer), buffer});
	}

	@Override
	public void read(ByteBuffer buffer) throws IOException {
		requireOpen();

		interface TempHolder {
			ThreadLocal<ByteBuffer> PACKET_FAMILY = ThreadLocal.withInitial(() -> ByteBuffer.allocateDirect(4));
		}
		inputChannel.read(new ByteBuffer[]{TempHolder.PACKET_FAMILY.get().clear(), buffer});
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
		inputChannel.close();
		outputChannel.close();
	}

	@Override
	public void addSubnet(Subnet subnet) throws IOException {
		try {
			if (subnet.isIPv4())
				runCommand("ifconfig", name(), "inet", subnet.toCIDRString(), subnet.address().getHostAddress(), "alias");
			else
				runCommand("ifconfig", name(), "inet6", subnet.toCIDRString(), "alias");
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		} catch (IOException ex) {
			throw new BindException("Could not add subnet " + subnet);
		}
	}

	@Override
	public void removeSubnet(Subnet subnet) throws IOException {
		try {
			if (subnet.isIPv4())
				runCommand("ifconfig", name(), "inet", subnet.toCIDRString(), subnet.address().getHostAddress(), "-alias");
			else
				runCommand("ifconfig", name(), "inet6", subnet.toCIDRString(), "-alias");
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	public static void runCommand(String... command) throws IOException, InterruptedException {
		var pb = new ProcessBuilder();
		pb.command(command);

		logger.log(DEBUG, "> " + String.join(" ", command));

		var process = pb.start();

		if (process.waitFor() != 0) {
			var result = new String(process.getInputStream().readAllBytes());
			throw new IOException("Command %s failed with exit code %d:  %s".formatted(String.join(" ", command), process.exitValue(), result));
		}

		var result = new String(process.getInputStream().readAllBytes());
		if (!result.isEmpty())
			logger.log(DEBUG, result);
	}

	private static native int AFINET();
	private static native int AFINET6();
}
