package ax.xz;

import java.io.IOException;

public class CommandUtils {
	public static String runCommand(String... command) throws IOException, InterruptedException {
		var pb = new ProcessBuilder();
		pb.command(command);

		System.out.println("> " + String.join(" ", command));

		var process = pb.start();

		if (process.waitFor() != 0) {
			var result = new String(process.getInputStream().readAllBytes());
			System.err.print(result);
			System.err.flush();
			throw new IOException();
		}
		var result = new String(process.getInputStream().readAllBytes());

		System.out.print(result);
		System.out.flush();
		return result;
	}
}
