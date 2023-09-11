package ax.xz.wireguard.noise.handshake;

import ax.xz.wireguard.noise.crypto.chacha20poly1305;
import ax.xz.wireguard.noise.crypto.internal.Blake2s;
import ax.xz.wireguard.noise.keys.NoisePresharedKey;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.crypto.BadPaddingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;

import static ax.xz.wireguard.noise.crypto.Crypto.*;
import static java.lang.System.Logger;
import static java.lang.System.Logger.Level.DEBUG;

public class Handshakes {
	private static final byte[] ZeroNonce = new byte[chacha20poly1305.NonceSize];
	private static final byte[] NOISE_CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".getBytes(StandardCharsets.UTF_8);
	private static final byte[] WG_IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com".getBytes(StandardCharsets.UTF_8);

	private static final byte[] INITIAL_CHAIN_KEY = BLAKE2s256(NOISE_CONSTRUCTION);
	private static final byte[] INITIAL_HASH = getInitialHash();

	private static byte[] getInitialHash() {
		var result = new byte[32];
		try {
			var hash = new Blake2s(32);
			hash.update(INITIAL_CHAIN_KEY);
			hash.update(WG_IDENTIFIER);
			hash.digest(result, 0, INITIAL_CHAIN_KEY.length);
		} catch (DigestException e) {
			throw new RuntimeException(e);
		}
		return result;
	}

	public static InitiatorStageOne initiateHandshake(NoisePrivateKey localKeypair, NoisePublicKey remotePublicKey, NoisePresharedKey presharedKey) {
		return new InitiatorStageOne(localKeypair, remotePublicKey, presharedKey);
	}

	public static ResponderHandshake responderHandshake(NoisePrivateKey localKeypair, NoisePublicKey remoteEphemeral, byte[] encryptedStatic, byte[] encryptedTimestamp) throws BadPaddingException {
		return new ResponderHandshake(localKeypair, remoteEphemeral, encryptedStatic, encryptedTimestamp);
	}

	public static class InitiatorStageOne {
		private static final Logger logger = System.getLogger(InitiatorStageOne.class.getName());

		private final byte[] hash = INITIAL_HASH.clone();
		private final byte[] chainKey = INITIAL_CHAIN_KEY.clone();

		private final NoisePrivateKey localEphemeral;
		private final NoisePrivateKey localKeypair;
		private final NoisePresharedKey presharedKey;

		private final byte[] encryptedStatic = new byte[chacha20poly1305.Overhead + NoisePublicKey.LENGTH];
		private final byte[] encryptedTimestamp = new byte[chacha20poly1305.Overhead + 12];

		private InitiatorStageOne(NoisePrivateKey localKeypair, NoisePublicKey remotePublicKey, NoisePresharedKey presharedKey) {
			this.localEphemeral = NoisePrivateKey.newPrivateKey();
			this.localKeypair = localKeypair;
			this.presharedKey = presharedKey;

			var ephemeral = localEphemeral.publicKey();
			// create ephemeral key
			updateHMAC(hash, remotePublicKey.data());
			KDF1(chainKey, chainKey, ephemeral.data());
			updateHMAC(hash, ephemeral.data());

			// encrypt static key
			byte[] key = new byte[chacha20poly1305.KeySize];
			KDF2(chainKey, key, chainKey, localEphemeral.sharedSecret(remotePublicKey).data());

			chacha20poly1305.cipher(key, ByteBuffer.wrap(localKeypair.publicKey().data()), ByteBuffer.wrap(encryptedStatic), new byte[chacha20poly1305.NonceSize], hash);
			updateHMAC(hash, encryptedStatic);

			// encrypt timestamp
			KDF2(chainKey, key, chainKey, localKeypair.sharedSecret(remotePublicKey).data());
			chacha20poly1305.cipher(key, ByteBuffer.wrap(TAI64N()), ByteBuffer.wrap(encryptedTimestamp), new byte[chacha20poly1305.NonceSize], hash);

			updateHMAC(hash, encryptedTimestamp);
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

		public SymmetricKeypair consumeMessageResponse(NoisePublicKey remoteEphemeral, byte[] encryptedEmpty) throws BadPaddingException {
			// lookup handshake by receiver
			// finish 3-way DH
			updateHMAC(hash, remoteEphemeral.data());
			KDF1(chainKey, chainKey, remoteEphemeral.data());

			KDF1(chainKey, chainKey, localEphemeral.sharedSecret(remoteEphemeral).data());
			KDF1(chainKey, chainKey, localKeypair.sharedSecret(remoteEphemeral).data());

			// add preshared key (psk)
			byte[] tau = new byte[TauSize];
			byte[] key = new byte[chacha20poly1305.KeySize];
			KDF3(chainKey, tau, key, chainKey, presharedKey.data());
			updateHMAC(hash, tau);

			// authenticate transcript
			chacha20poly1305.decipher(key, ByteBuffer.wrap(encryptedEmpty), ByteBuffer.allocate(0), ZeroNonce, hash);
			updateHMAC(hash, encryptedEmpty);

			// create send/receive keys
			byte[] sendKey = new byte[chacha20poly1305.KeySize];
			byte[] receiveKey = new byte[chacha20poly1305.KeySize];

			KDF2(sendKey, receiveKey, this.chainKey, new byte[0]);
			var kp = new SymmetricKeypair(sendKey, receiveKey);

			logger.log(DEBUG, "DH key exchange completed");
			return kp;
		}

	}

	public static class ResponderHandshake {
		private final byte[] encryptedEmpty = new byte[chacha20poly1305.Overhead];

		private final SymmetricKeypair keypair;
		private final NoisePublicKey remotePublicKey, localEphemeral;

		public ResponderHandshake(NoisePrivateKey localKeypair, NoisePublicKey remoteEphemeral, byte[] encryptedStatic, byte[] encryptedTimestamp) throws BadPaddingException {
			var hash = INITIAL_HASH.clone();
			var chainKey = INITIAL_CHAIN_KEY.clone();

			NoisePrivateKey localEphemeral = NoisePrivateKey.newPrivateKey();
			this.localEphemeral = localEphemeral.publicKey();

			updateHMAC(hash, localKeypair.publicKey().data());
			updateHMAC(hash, remoteEphemeral.data());
			KDF1(chainKey, chainKey, remoteEphemeral.data());

			{
				byte[] remoteStatic = new byte[NoisePublicKey.LENGTH];
				byte[] key = new byte[chacha20poly1305.KeySize];
				byte[] ss = localKeypair.sharedSecret(remoteEphemeral).data();

				KDF2(chainKey, key, chainKey, ss);
				chacha20poly1305.decipher(key, ByteBuffer.wrap(encryptedStatic), ByteBuffer.wrap(remoteStatic), ZeroNonce, hash);
				updateHMAC(hash, encryptedStatic);

				// verify identity
				remotePublicKey = new NoisePublicKey(remoteStatic);
				var staticStatic = localKeypair.sharedSecret(remotePublicKey);
				KDF2(chainKey, key, chainKey, staticStatic.data());
				updateHMAC(hash, encryptedTimestamp);
			}

			 {
				// create ephemeral key
				updateHMAC(hash, localEphemeral.publicKey().data());
				KDF1(chainKey, chainKey, localEphemeral.publicKey().data());

				KDF1(chainKey, chainKey, localEphemeral.sharedSecret(remoteEphemeral).data());
				KDF1(chainKey, chainKey, localEphemeral.sharedSecret(remotePublicKey).data());

				// add preshared key
				byte[] tau = new byte[BLAKE2S_SIZE_256];
				byte[] key = new byte[chacha20poly1305.KeySize];

				NoisePresharedKey presharedKey = new NoisePresharedKey(new byte[NoisePresharedKey.LENGTH]);
				KDF3(chainKey, tau, key, chainKey, presharedKey.data());

				updateHMAC(hash, tau);

				chacha20poly1305.cipher(key, ByteBuffer.allocate(0), ByteBuffer.wrap(encryptedEmpty), ZeroNonce, hash);
				updateHMAC(hash, encryptedEmpty);

				byte[] sendKey = new byte[chacha20poly1305.KeySize];
				byte[] receiveKey = new byte[chacha20poly1305.KeySize];

				KDF2(receiveKey, sendKey, chainKey, new byte[0]);

				this.keypair = new SymmetricKeypair(sendKey, receiveKey);
			}
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
			return localEphemeral;
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
		}
	}
}
