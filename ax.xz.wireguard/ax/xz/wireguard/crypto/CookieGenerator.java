package ax.xz.wireguard.crypto;

import org.bouncycastle.crypto.digests.Blake2sDigest;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class CookieGenerator {
	private static final byte[] WG_LABEL_MAC1 = "mac1----".getBytes(StandardCharsets.UTF_8);
	private static final byte[] WG_LABEL_COOKIE = "cookie--".getBytes(StandardCharsets.UTF_8);


	public static void appendMacs(NoisePublicKey pk, ByteBuffer msg) {
		byte[] mac1Key;
		byte[] mac2Cookie;

		{
			var hash = new Blake2sDigest(256);
			hash.update(WG_LABEL_MAC1, 0, WG_LABEL_MAC1.length);
			hash.update(pk.data(), 0, NoisePublicKey.LENGTH);
			mac1Key = new byte[32];
			hash.doFinal(mac1Key, 0);
		}

		{
			var hash = new Blake2sDigest(256);
			hash.update(WG_LABEL_COOKIE, 0, WG_LABEL_COOKIE.length);
			hash.update(pk.data(), 0, NoisePublicKey.LENGTH);
			mac2Cookie = new byte[32];
			hash.doFinal(mac2Cookie, 0);
		}

		var hash = new Blake2sDigest(mac1Key, 128 / 8, null, null);

		var len = msg.position();
		byte[] slice = new byte[len];
		msg.slice(0, len).get(slice);
		hash.update(slice, 0, slice.length);

		byte[] mac1 = new byte[16];
		hash.doFinal(mac1, 0);
		msg.put(mac1);

		// mac 2
		msg.put(new byte[16]);
	}
}
