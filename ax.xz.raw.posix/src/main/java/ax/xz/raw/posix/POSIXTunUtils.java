package ax.xz.raw.posix;

import java.io.IOException;
import java.nio.ByteBuffer;

public class POSIXTunUtils {
	static final int AF_INET = AFINET();
	static final int AF_INET6 = AFINET6();

	private static native int AFINET();

	private static native int AFINET6();

	/**
	 * Gets a ByteBuffer containing the address family of the given IP packet
	 * @param packet the IP packet
	 * @return a ByteBuffer containing the address family of the given IP packet
	 * @throws IOException if the IP version is not 4 or 6
	 */
	static ByteBuffer getPacketFamily(ByteBuffer packet) throws IOException {
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
}
