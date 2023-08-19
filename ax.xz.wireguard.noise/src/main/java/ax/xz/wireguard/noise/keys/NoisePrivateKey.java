package ax.xz.wireguard.noise.keys;

import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.encoders.Base64;

import java.io.Serializable;
import java.security.SecureRandom;

import java.util.Objects;

public record NoisePrivateKey(byte[] data, NoisePublicKey publicKey) implements Serializable {
   public static final int LENGTH = 32;

   public NoisePrivateKey {
	  Objects.requireNonNull(data);
	  Objects.requireNonNull(publicKey);

	  if (data.length != LENGTH) {
		 throw new IllegalArgumentException("NoisePrivateKey must be 32 bytes");
	  }
   }

   NoisePrivateKey(byte[] data) {
	   this(data, new NoisePublicKey(getPublicKey(data)));
   }

   private static byte[] getPublicKey(byte[] privateKey) {
	   byte[] publicKey = new byte[NoisePublicKey.LENGTH];
	   X25519.generatePublicKey(privateKey, 0, publicKey, 0);
	   return publicKey;
   }

   public static NoisePrivateKey newPrivateKey() {
	   var secureRandom = new SecureRandom();
		byte[] pk = new byte[LENGTH];

		X25519.generatePrivateKey(secureRandom, pk);
	   return new NoisePrivateKey(pk);
   }

   public NoisePublicKey sharedSecret(NoisePublicKey publicKey) {
	   byte[] sharedSecret = new byte[NoisePublicKey.LENGTH];
	   X25519.calculateAgreement(data, 0, publicKey.data(), 0, sharedSecret, 0);
	   return new NoisePublicKey(sharedSecret);
   }

   public static NoisePrivateKey fromBase64(String base64) {
	   return new NoisePrivateKey(Base64.decode(base64));
   }
}
