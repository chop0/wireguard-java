package ax.xz.wireguard.device.message.initiation;

import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.noise.handshake.Handshakes;
import ax.xz.wireguard.noise.keys.NoisePrivateKey;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.crypto.BadPaddingException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.util.Arrays;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

public final class IncomingInitiation extends InitiationPacket implements IncomingPeerPacket {
	private final InetSocketAddress sender;
	private final NoisePublicKey remotePublicKey;

	public IncomingInitiation(UnparsedIncomingPeerPacket data, NoisePrivateKey localIdentity, InetSocketAddress sender) throws BadPaddingException {
		super(data);
		this.sender = sender;

		if ((byte) InitiationPacket.MESSAGE_TYPE.get(header) != InitiationPacket.TYPE) {
			throw new IllegalArgumentException("Invalid message type (expected " + InitiationPacket.TYPE + " but got " + header.get(JAVA_BYTE, 0) + ")");
		}

		byte[] mac1 = new byte[16];
		byte[] mac2 = new byte[16];

		try {
			MemorySegment.ofArray(mac1).copyFrom((MemorySegment) MAC1.invokeExact(header));
			MemorySegment.ofArray(mac2).copyFrom((MemorySegment) MAC2.invokeExact(header));
		} catch (Throwable e) {
			throw new Error(e);
		}

		byte[] mac1Calculated = calculateMac1(localIdentity.publicKey());
		if (!Arrays.equals(mac1, mac1Calculated))
			throw new BadPaddingException("Invalid MAC1 (expected " + Arrays.toString(mac1Calculated) + " but got " + Arrays.toString(mac1) + ")");

		byte[] mac2Calculated = new byte[16];
		if (!Arrays.equals(mac2, mac2Calculated))
			throw new BadPaddingException("Invalid MAC2 (expected " + Arrays.toString(mac2Calculated) + " but got " + Arrays.toString(mac2) + ")");

		this.remotePublicKey = Handshakes.decryptRemoteStatic(localIdentity, ephemeral(), encryptedStatic(), encryptedTimestamp());
	}

	public InetSocketAddress originAddress() {
		return sender;
	}

	public NoisePublicKey remotePublicKey() {
		return remotePublicKey;
	}

	@Override
	public long length() {
		return InitiationPacket.HEADER_LAYOUT.byteSize();
	}
}
