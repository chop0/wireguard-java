package ax.xz.wireguard;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

public class IPUtils {
	public static InetAddress fullNetmask(boolean isIpv6) {
		var maskBytes = new byte[isIpv6 ? 16 : 4];
		Arrays.fill(maskBytes, (byte) 0xff);

		try {
			return InetAddress.getByAddress(maskBytes);
		} catch (UnknownHostException e) {
			throw new Error(e);
		}
	}

	public static InetAddress emptyNetmask(boolean isIpv6) {
		try {
			return InetAddress.getByAddress(new byte[isIpv6 ? 16 : 4]);
		} catch (UnknownHostException e) {
			throw new RuntimeException(e);
		}
	}

	public static InetAddress netmaskFromPrefixLength(int i, boolean isIpv6) {
		var maskBytes = new byte[isIpv6 ? 16 : 4];

		for (int j = 0; j < i; j++) {
			maskBytes[j / 8] |= (byte) (1 << (7 - j % 8));
		}

		try {
			return InetAddress.getByAddress(maskBytes);
		} catch (UnknownHostException e) {
			throw new Error(e);
		}
	}
}
