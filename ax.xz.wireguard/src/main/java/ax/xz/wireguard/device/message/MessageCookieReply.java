//package ax.xz.wireguard.device.message;
//
//import ax.xz.wireguard.noise.crypto.Crypto;
//
//public record MessageCookieReply(int type, int receiver, byte[] nonce, byte[] cookie) implements Message {
//	public MessageCookieReply {
//		if (type != 3)
//			throw new IllegalArgumentException("type must be 3");
//
//		if (nonce.length != Crypto.POLY1305_NONCE_SIZE)
//			throw new IllegalArgumentException("nonce must be 192 bits (24 bytes)");
//
//		if (cookie.length != Crypto.BLAKE2S_SIZE_128 + Crypto.POLY1305_TAG_SIZE)
//			throw new IllegalArgumentException("cookie must be 128 bits (16 bytes) + tag size (16) bytes");
//	}
//}
