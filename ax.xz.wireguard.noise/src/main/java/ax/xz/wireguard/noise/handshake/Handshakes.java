package ax.xz.wireguard.noise.handshake;

import ax.xz.wireguard.noise.crypto.internal.Blake2s;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.foreign.Arena;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

import static ax.xz.wireguard.noise.crypto.Crypto.*;
import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;

public class Handshakes {
	private static final byte[] ZeroNonce = new byte[ChaChaPoly1305NonceSize];
	private static final byte[] NOISE_CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(StandardCharsets.UTF_8);
	private static final byte[] WG_IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(StandardCharsets.UTF_8);

	private static final byte[] INITIAL_CHAIN_KEY = BLAKE2s256(NOISE_CONSTRUCTION);
	private static final byte[] INITIAL_HASH;

	static {
		var result = new byte[32];
		try {
			var hash = new Blake2s(32);
			hash.update(INITIAL_CHAIN_KEY);
			hash.update(WG_IDENTIFIER);
			hash.digest(result, 0, INITIAL_CHAIN_KEY.length);
		} catch (DigestException e) {
			throw new RuntimeException(e);
		}
		INITIAL_HASH = result;
	}

	public static InitiatorStageOne initiateHandshake(NoisePrivateKey localKeypair, NoisePublicKey remotePublicKey, NoisePresharedKey presharedKey) {
		return new InitiatorStageOne(localKeypair, remotePublicKey, presharedKey);
	}

	public static ResponderHandshake responderHandshake(NoisePrivateKey localKeypair, NoisePublicKey remoteEphemeral, byte[] encryptedStatic, byte[] encryptedTimestamp) throws BadPaddingException {
		return new ResponderHandshake(localKeypair, remoteEphemeral, encryptedStatic, encryptedTimestamp);
	}

	public static NoisePublicKey decryptRemoteStatic(NoisePrivateKey localKeypair, NoisePublicKey remoteEphemeral, byte[] encryptedStatic, byte[] encryptedTimestamp) throws BadPaddingException {
		var state = ResponderHandshake.HandshakeState.initial();
		return ResponderHandshake.decryptRemoteStatic(localKeypair, remoteEphemeral, encryptedStatic, encryptedTimestamp, state);
	}

	public static class InitiatorStageOne {
		private static final Logger logger = System.getLogger(InitiatorStageOne.class.getName());

		private final Cipher chacha20;

		{
			try {
				chacha20 = Cipher.getInstance("ChaCha20-Poly1305");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException(e);
			} catch (NoSuchPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		private final byte[] hash = INITIAL_HASH.clone();
		private byte[] chainKey = INITIAL_CHAIN_KEY;

		private final NoisePrivateKey localEphemeral;
		private final NoisePrivateKey localKeypair;
		private final NoisePresharedKey presharedKey;

		private final byte[] encryptedStatic = new byte[ChaChaPoly1305Overhead + NoisePublicKey.LENGTH];
		private final byte[] encryptedTimestamp = new byte[ChaChaPoly1305Overhead + 12];

		private InitiatorStageOne(NoisePrivateKey localKeypair, NoisePublicKey remotePublicKey, NoisePresharedKey presharedKey) {
			this.localEphemeral = NoisePrivateKey.newPrivateKey();
			this.localKeypair = localKeypair;
			this.presharedKey = presharedKey;

			var ephemeral = localEphemeral.publicKey();
			// create ephemeral key
			updateHMAC(hash, remotePublicKey.data());
			chainKey = deriveKey(chainKey, ephemeral.data());
			updateHMAC(hash, ephemeral.data());

			// encrypt static key
			var key = new SecretKeySpec(deriveKey(chainKey, localEphemeral.sharedSecret(remotePublicKey).data(), 2), "ChaCha20-Poly1305");
			chainKey = deriveKey(chainKey, localEphemeral.sharedSecret(remotePublicKey).data(), 1);

			try {
				chacha20.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ZeroNonce));
				chacha20.updateAAD(hash);
				chacha20.doFinal(localKeypair.publicKey().data(), 0, NoisePublicKey.LENGTH, encryptedStatic);

				updateHMAC(hash, encryptedStatic);

				// encrypt timestamp
				key = new SecretKeySpec(deriveKey(chainKey, localKeypair.sharedSecret(remotePublicKey).data(), 2), "ChaCha20-Poly1305");
				chainKey = deriveKey(chainKey, localKeypair.sharedSecret(remotePublicKey).data(), 1);

				chacha20.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ZeroNonce));
				chacha20.updateAAD(hash);
				chacha20.doFinal(TAI64N(), 0, 12, encryptedTimestamp);
			} catch (
				ShortBufferException |
				IllegalBlockSizeException |
				BadPaddingException |
				InvalidAlgorithmParameterException |
				InvalidKeyException e
			) {
				throw new RuntimeException(e);
			}

			updateHMAC(hash, encryptedTimestamp);
		}

		public SymmetricKeypair consumeMessageResponse(NoisePublicKey remoteEphemeral, byte[] encryptedEmpty) throws BadPaddingException {
			// lookup handshake by receiver
			// finish 3-way DH
			updateHMAC(hash, remoteEphemeral.data());
			chainKey = deriveKey(chainKey, remoteEphemeral.data());

			chainKey = deriveKey(chainKey, localEphemeral.sharedSecret(remoteEphemeral).data());
			chainKey = deriveKey(chainKey, localKeypair.sharedSecret(remoteEphemeral).data());

			// add preshared key (psk)
			byte[] tau = deriveKey(chainKey, presharedKey.data(), 2);
			var key = new SecretKeySpec(deriveKey(chainKey, presharedKey.data(), 3), "ChaCha20-Poly1305");
			chainKey = deriveKey(chainKey, presharedKey.data(), 1);

			updateHMAC(hash, tau);

			try {
				chacha20.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ZeroNonce));

				chacha20.updateAAD(hash);
				chacha20.doFinal(encryptedEmpty);
			} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
				throw new IllegalArgumentException(e);
			} catch (IllegalBlockSizeException e) {
				throw new Error("unexpected error (we're using a stream cipher)", e);
			}
			updateHMAC(hash, encryptedEmpty);

			// create send/receive keys
			var sendKey = new SecretKeySpec(deriveKey(chainKey, new byte[0], 1), "ChaCha20-Poly1305");
			var receiveKey = new SecretKeySpec(deriveKey(chainKey, new byte[0], 2), "ChaCha20-Poly1305");

			var kp = new SymmetricKeypair(sendKey, receiveKey);

			logger.log(DEBUG, "DH key exchange completed");
			return kp;
		}

		public NoisePrivateKey getLocalEphemeral() {
			return localEphemeral;
		}

		public byte[] getEncryptedStatic() {
			return encryptedStatic;
		}

		public byte[] getEncryptedTimestamp() {
			return encryptedTimestamp;
		}
	}

	public static class ResponderHandshake {
		private final byte[] encryptedEmpty = new byte[ChaChaPoly1305Overhead];

		private static Cipher getCipher() {
			try {
				return Cipher.getInstance("ChaCha20-Poly1305");
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				throw new RuntimeException(e);
			}
		}

		private final SymmetricKeypair keypair;
		private final NoisePublicKey remotePublicKey;
		private final NoisePrivateKey localEphemeral;

		ResponderHandshake(NoisePrivateKey localKeypair, NoisePublicKey remoteEphemeral, byte[] encryptedStatic, byte[] encryptedTimestamp) throws BadPaddingException {
			this.localEphemeral = NoisePrivateKey.newPrivateKey();

			var state = HandshakeState.initial();

			this.remotePublicKey = decryptRemoteStatic(localKeypair, remoteEphemeral, encryptedStatic, encryptedTimestamp, state);
			this.keypair = deriveKeypair(state, localEphemeral, remoteEphemeral, remotePublicKey, encryptedEmpty);
		}

		/**
		 * Does the first phase of the responder handshake, which decrypts the remote static key and verifies the identity of the initiator.
		 *
		 * @param localKeypair       the local keypair
		 * @param remoteEphemeral    the remote ephemeral key
		 * @param encryptedStatic    the encrypted static key
		 * @param encryptedTimestamp the encrypted timestamp
		 * @param state              the state of the handshake (should be {@link HandshakeState#initial()} when this method is called)
		 * @return the remote static key
		 * @throws BadPaddingException if the encrypted static key or the encrypted timestamp are invalid
		 */
		private static NoisePublicKey decryptRemoteStatic(NoisePrivateKey localKeypair, NoisePublicKey remoteEphemeral, byte[] encryptedStatic, byte[] encryptedTimestamp, HandshakeState state) throws BadPaddingException {
			final var hash = state.hash;
			final var chainKey = state.chainKey;

			updateHMAC(hash, localKeypair.publicKey().data());
			updateHMAC(hash, remoteEphemeral.data());
			state.setChainKey(deriveKey(chainKey, remoteEphemeral.data()));

			byte[] remoteStatic = new byte[NoisePublicKey.LENGTH];
			byte[] ss = localKeypair.sharedSecret(remoteEphemeral).data();

			var key = new SecretKeySpec(deriveKey(chainKey, ss, 2), "ChaCha20-Poly1305");
			state.setChainKey(deriveKey(chainKey, ss, 1));

			try {
				var chacha20 = getCipher();

				chacha20.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ZeroNonce));

				chacha20.updateAAD(hash);
				chacha20.doFinal(encryptedStatic, 0, encryptedStatic.length, remoteStatic);
			} catch (ShortBufferException | InvalidKeyException | InvalidAlgorithmParameterException e) {
				throw new IllegalArgumentException(e);
			} catch (IllegalBlockSizeException e) {
				throw new Error("unexpected error (we're using a stream cipher)", e);
			}

			updateHMAC(hash, encryptedStatic);

			// verify identity
			var remotePublicKey = new NoisePublicKey(remoteStatic);
			var staticStatic = localKeypair.sharedSecret(remotePublicKey);
			state.setChainKey(deriveKey(chainKey, staticStatic.data()));
			updateHMAC(hash, encryptedTimestamp);

			return remotePublicKey;
		}

		/**
		 * Does the second phase of the responder handshake, which derives the symmetric keys
		 * @param state the state of the handshake (should be the state left by {@link #decryptRemoteStatic(NoisePrivateKey, NoisePublicKey, byte[], byte[], HandshakeState)} when this method is called)
		 *
		 * @param localEphemeral the local ephemeral key
		 * @param remoteEphemeral the remote ephemeral key
		 *
		 * @param remotePublicKey the remote static key
		 * @param encryptedEmpty the encrypted empty message
		 * @return the symmetric keypair
		 */
		private static SymmetricKeypair deriveKeypair(HandshakeState state, NoisePrivateKey localEphemeral, NoisePublicKey remoteEphemeral, NoisePublicKey remotePublicKey, byte[] encryptedEmpty) {
			final var hash = state.hash;
			final var chainKey = state.chainKey;

			// create ephemeral key
			updateHMAC(hash, localEphemeral.publicKey().data());
			state.setChainKey(deriveKey(chainKey, localEphemeral.publicKey().data()));

			state.setChainKey(deriveKey(chainKey, localEphemeral.sharedSecret(remoteEphemeral).data()));
			state.setChainKey(deriveKey(chainKey, localEphemeral.sharedSecret(remotePublicKey).data()));

			// add preshared key
			NoisePresharedKey presharedKey = new NoisePresharedKey(new byte[NoisePresharedKey.LENGTH]);

			var tau = deriveKey(chainKey, presharedKey.data(), 2);
			var key = new SecretKeySpec(deriveKey(chainKey, presharedKey.data(), 3), "ChaCha20-Poly1305");
			state.setChainKey(deriveKey(chainKey, presharedKey.data(), 1));

			updateHMAC(hash, tau);

			try {
				var chacha20 = getCipher();

				chacha20.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ZeroNonce));
				chacha20.updateAAD(hash);
				chacha20.doFinal(encryptedEmpty, 0);
			} catch (
				ShortBufferException |
				IllegalBlockSizeException |
				BadPaddingException |
				InvalidAlgorithmParameterException |
				InvalidKeyException e
			) {
				throw new RuntimeException(e);
			}
			updateHMAC(hash, encryptedEmpty);

			var sendKey = new SecretKeySpec(deriveKey(chainKey, new byte[0], 2), "ChaCha20-Poly1305");
			var receiveKey = new SecretKeySpec(deriveKey(chainKey, new byte[0], 1), "ChaCha20-Poly1305");

			return new SymmetricKeypair(sendKey, receiveKey);
		}

		public SymmetricKeypair getKeypair() {
			return keypair;
		}

		public NoisePublicKey getRemotePublicKey() {
			return remotePublicKey;
		}

		public byte[] getEncryptedEmpty() {
			return encryptedEmpty;
		}

		public NoisePublicKey getLocalEphemeral() {
			return localEphemeral.publicKey();
		}

		private record HandshakeState(byte[] hash, byte[] chainKey) {
			static HandshakeState initial() {
				return new HandshakeState(INITIAL_HASH.clone(), INITIAL_CHAIN_KEY.clone());
			}

			void setHash(byte[] hash) {
				System.arraycopy(hash, 0, this.hash, 0, hash.length);
			}

			void setChainKey(byte[] chainKey) {
				System.arraycopy(chainKey, 0, this.chainKey, 0, chainKey.length);
			}
		}
	}

	private static void updateHMAC(byte[] hmac, byte[] data) {
		interface DigestHolder {
			ThreadLocal<MessageDigest> INSTANCE = ThreadLocal.withInitial(() -> new Blake2s(32));
		}

		var messageDigest = DigestHolder.INSTANCE.get();
		try {
			messageDigest.update(hmac);
			messageDigest.update(data);
			messageDigest.digest(hmac, 0, hmac.length);
		} catch (DigestException e) {
			throw new RuntimeException(e);
		} finally {
			messageDigest.reset();
		}
	}

	private Handshakes() {
	}
}
