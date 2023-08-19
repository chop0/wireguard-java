package ax.xz.wireguard.device;

import java.io.Serializable;

public record DeviceStats(int numPeers, int numHandshakes, long numBytesSent,
						  long numBytesReceived) implements Serializable {
	@Override
	public String toString() {
		return "DeviceStats[" +
			   "numPeers=" + numPeers +
			   ", numHandshakes=" + numHandshakes +
			   ", numBytesSent=" + bytesToString(numBytesSent) +
			   ", numBytesReceived=" + bytesToString(numBytesReceived) +
			   ']';
	}

	private static String bytesToString(long bytes) {
		if (bytes < 1024) {
			return bytes + " B";
		} else if (bytes < 1024 * 1024) {
			return String.format("%.2f KiB", bytes / 1024.0);
		} else if (bytes < 1024 * 1024 * 1024) {
			return String.format("%.2f MiB", bytes / (1024.0 * 1024.0));
		} else {
			return String.format("%.2f GiB", bytes / (1024.0 * 1024.0 * 1024.0));
		}
	}
}
