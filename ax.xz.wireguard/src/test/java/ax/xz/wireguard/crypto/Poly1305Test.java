package ax.xz.wireguard.crypto;

import ax.xz.wireguard.crypto.Poly1305;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class Poly1305Test {

	@Test
	void poly1305AeadEncrypt() {
		var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

		byte[] aad = {
			(byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53,
			(byte) 0xc0, (byte) 0xc1, (byte) 0xc2, (byte) 0xc3,
			(byte) 0xc4, (byte) 0xc5, (byte) 0xc6, (byte) 0xc7
		};

		byte[] key = {
			(byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83,
			(byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
			(byte) 0x88, (byte) 0x89, (byte) 0x8a, (byte) 0x8b,
			(byte) 0x8c, (byte) 0x8d, (byte) 0x8e, (byte) 0x8f,
			(byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93,
			(byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
			(byte) 0x98, (byte) 0x99, (byte) 0x9a, (byte) 0x9b,
			(byte) 0x9c, (byte) 0x9d, (byte) 0x9e, (byte) 0x9f
		};

		byte[] nonce = {
			0x07, 0x00, 0x00, 0x00,
			0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47
		};

		byte[] expectedCiphertext = {
			(byte) 0xd3, (byte) 0x1a, (byte) 0x8d, (byte) 0x34, (byte) 0x64, (byte) 0x8e, (byte) 0x60, (byte) 0xdb, (byte) 0x7b, (byte) 0x86, (byte) 0xaf, (byte) 0xbc, (byte) 0x53, (byte) 0xef, (byte) 0x7e, (byte) 0xc2,
			(byte) 0xa4, (byte) 0xad, (byte) 0xed, (byte) 0x51, (byte) 0x29, (byte) 0x6e, (byte) 0x08, (byte) 0xfe, (byte) 0xa9, (byte) 0xe2, (byte) 0xb5, (byte) 0xa7, (byte) 0x36, (byte) 0xee, (byte) 0x62, (byte) 0xd6,
			(byte) 0x3d, (byte) 0xbe, (byte) 0xa4, (byte) 0x5e, (byte) 0x8c, (byte) 0xa9, (byte) 0x67, (byte) 0x12, (byte) 0x82, (byte) 0xfa, (byte) 0xfb, (byte) 0x69, (byte) 0xda, (byte) 0x92, (byte) 0x72, (byte) 0x8b,
			(byte) 0x1a, (byte) 0x71, (byte) 0xde, (byte) 0x0a, (byte) 0x9e, (byte) 0x06, (byte) 0x0b, (byte) 0x29, (byte) 0x05, (byte) 0xd6, (byte) 0xa5, (byte) 0xb6, (byte) 0x7e, (byte) 0xcd, (byte) 0x3b, (byte) 0x36,
			(byte) 0x92, (byte) 0xdd, (byte) 0xbd, (byte) 0x7f, (byte) 0x2d, (byte) 0x77, (byte) 0x8b, (byte) 0x8c, (byte) 0x98, (byte) 0x03, (byte) 0xae, (byte) 0xe3, (byte) 0x28, (byte) 0x09, (byte) 0x1b, (byte) 0x58,
			(byte) 0xfa, (byte) 0xb3, (byte) 0x24, (byte) 0xe4, (byte) 0xfa, (byte) 0xd6, (byte) 0x75, (byte) 0x94, (byte) 0x55, (byte) 0x85, (byte) 0x80, (byte) 0x8b, (byte) 0x48, (byte) 0x31, (byte) 0xd7, (byte) 0xbc,
			(byte) 0x3f, (byte) 0xf4, (byte) 0xde, (byte) 0xf0, (byte) 0x8e, (byte) 0x4b, (byte) 0x7a, (byte) 0x9d, (byte) 0xe5, (byte) 0x76, (byte) 0xd2, (byte) 0x65, (byte) 0x86, (byte) 0xce, (byte) 0xc6, (byte) 0x4b,
			(byte) 0x61, (byte) 0x16
		};

		byte[] expectedTag = {
			(byte) 0x1a, (byte) 0xe1, (byte) 0x0b, (byte) 0x59, (byte) 0x4f, (byte) 0x09, (byte) 0xe2, (byte) 0x6a, (byte) 0x7e, (byte) 0x90, (byte) 0x2e, (byte) 0xcb, (byte) 0xd0, (byte) 0x60, (byte) 0x06, (byte) 0x91
		};

		byte[] output = new byte[plaintext.getBytes(UTF_8).length + 16];
		Poly1305.poly1305AeadEncrypt(aad, key, nonce, ByteBuffer.wrap(plaintext.getBytes(UTF_8)), ByteBuffer.wrap(output));

		var ciphertext = Arrays.copyOf(output, plaintext.length());
		var tag = Arrays.copyOfRange(output, output.length - 16, output.length);

		assertArrayEquals(expectedCiphertext, ciphertext);
		assertArrayEquals(expectedTag, tag);
	}

	@Test
	void poly1305AeadDecrypt() throws AEADBadTagException {
		var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		var aad = "Cryptographic Forum Research Group";

		var key = new byte[32];
		ThreadLocalRandom.current().nextBytes(key);

		var nonce = new byte[12];
		ThreadLocalRandom.current().nextBytes(nonce);

		byte[] ciphertext = new byte[plaintext.getBytes(UTF_8).length + 16];
		Poly1305.poly1305AeadEncrypt(aad.getBytes(UTF_8), key, nonce, ByteBuffer.wrap(plaintext.getBytes(UTF_8)), ByteBuffer.wrap(ciphertext));

		byte[] result = new byte[plaintext.getBytes(UTF_8).length];
		Poly1305.poly1305AeadDecrypt(aad.getBytes(UTF_8), key, nonce, ByteBuffer.wrap(ciphertext), ByteBuffer.wrap(result));
		assertArrayEquals(plaintext.getBytes(UTF_8), result);

		ciphertext[plaintext.length()] = (byte) ~ciphertext[plaintext.length()];
		assertThrows(AEADBadTagException.class, () -> Poly1305.poly1305AeadDecrypt(aad.getBytes(UTF_8), key, nonce, ByteBuffer.wrap(ciphertext), ByteBuffer.wrap(result)));
	}
}
