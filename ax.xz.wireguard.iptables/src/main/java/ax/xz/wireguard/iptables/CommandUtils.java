package ax.xz.wireguard.iptables;

import java.io.IOException;

import static java.lang.System.Logger.Level.DEBUG;

class CommandUtils {
	private static final System.Logger logger = System.getLogger(CommandUtils.class.getName());

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
}
