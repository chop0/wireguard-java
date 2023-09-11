package ax.xz.wireguard.noise.crypto;

import ax.xz.wireguard.noise.crypto.internal.Blake2s;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static ax.xz.wireguard.noise.crypto.Crypto.getBlake2s256;

public class CookieGenerator {
	private static final byte[] WG_LABEL_MAC1 = "mac1----".getBytes(StandardCharsets.UTF_8);
	private static final byte[] WG_LABEL_COOKIE = "cookie--".getBytes(StandardCharsets.UTF_8);


	public static void appendMacs(byte[] pk, ByteBuffer msg) {
		byte[] mac1Key;
		byte[] mac2Cookie;

		try {
			{
				var hash = getBlake2s256();
				hash.update(WG_LABEL_MAC1, 0, WG_LABEL_MAC1.length);
				hash.update(pk, 0, pk.length);
				mac1Key = new byte[32];
				hash.digest(mac1Key, 0, mac1Key.length);
			}

			{
				var hash = getBlake2s256();
				hash.update(WG_LABEL_COOKIE, 0, WG_LABEL_COOKIE.length);
				hash.update(pk, 0, pk.length);
				mac2Cookie = new byte[32];
				hash.digest(mac2Cookie, 0, mac2Cookie.length);
			}
		} catch (Exception e) {
			throw new RuntimeException(e); // TODO:  handle properly
		}

		var hash = new Blake2s(128 / 8, mac1Key);

		var len = msg.position();
		byte[] slice = new byte[len];
		msg.slice(0, len).get(slice);
		hash.update(slice, 0, slice.length);

		byte[] mac1 = hash.digest();
		msg.put(mac1);

		// mac 2
		msg.put(new byte[16]);
	}
}
