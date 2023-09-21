package ax.xz.wireguard.util;

import java.nio.ByteBuffer;

public class Hex {
	private static void hexPrint(byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			System.out.printf("0x%02x, ", bytes[i]);
			if (i % 16 == 15) {
				System.out.println();
			}
		}
		System.out.println();
	}

	public static void hexPrint(ByteBuffer bb) {
		bb = bb.duplicate();
		for (int i = 0; i < bb.limit(); i++) {
			System.out.printf("0x%02x, ", bb.get(i));
			if (i % 16 == 15) {
				System.out.println();
			}
		}
	}
}
