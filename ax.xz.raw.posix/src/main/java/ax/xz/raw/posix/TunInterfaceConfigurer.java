package ax.xz.raw.posix;

import ax.xz.raw.spi.Tun;

import java.io.IOException;
import java.util.Set;

import static java.lang.System.Logger.Level.DEBUG;

public interface TunInterfaceConfigurer {
	System.Logger logger = System.getLogger(TunInterfaceConfigurer.class.getName());

	void addSubnet(String ifName, Tun.Subnet subnet) throws IOException;
	void removeSubnet(String ifName, Tun.Subnet subnet) throws IOException;
	void up(String ifName) throws IOException;
	Set<Tun.Subnet> subnets(String ifName) throws IOException;

	static String runCommand(String... command) throws IOException, InterruptedException {
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

		return result;
	}

	private static boolean isBSD() {
		var name = System.getProperty("os.name").toLowerCase();
		return name.contains("bsd") || name.contains("os x");
	}

	private static boolean isLinux() {
		return System.getProperty("os.name").toLowerCase().contains("linux");
	}

	static TunInterfaceConfigurer get() {
		if (isLinux())
			return new IpTunInterfaceConfigurer();
		else if (isBSD())
			return new IfconfigTunInterfaceConfigurer();
		else
			throw new UnsupportedOperationException("Unsupported operating system:  " + System.getProperty("os.name"));
	}
}
