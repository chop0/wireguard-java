package ax.xz.wireguard.device.message.response;

import ax.xz.wireguard.device.message.IncomingPeerPacket;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import javax.crypto.BadPaddingException;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.util.Arrays;

public final class IncomingResponse extends ResponsePacket implements IncomingPeerPacket {
	private final InetSocketAddress sender;

	public IncomingResponse(UnparsedIncomingPeerPacket data, NoisePublicKey localPublicKey, InetSocketAddress sender) throws BadPaddingException {
		super(data);
		this.sender = sender;
		if ((byte) ResponsePacket.MESSAGE_TYPE.get(header) != ResponsePacket.TYPE)
			throw new IllegalArgumentException("Invalid message type (expected " + ResponsePacket.TYPE + " but got " + ResponsePacket.MESSAGE_TYPE.get(header) + ")");

		byte[] mac1 = new byte[16];
		byte[] mac2 = new byte[16];

		try {
			MemorySegment.ofArray(mac1).copyFrom((MemorySegment) MAC1.invokeExact(header));
			MemorySegment.ofArray(mac2).copyFrom((MemorySegment) MAC2.invokeExact(header));
		} catch (Throwable e) {
			throw new Error(e);
		}

		byte[] mac1Calculated = calculateMac1(localPublicKey);
		if (!Arrays.equals(mac1, mac1Calculated))
			throw new BadPaddingException("Invalid MAC1 (expected " + Arrays.toString(mac1Calculated) + " but got " + Arrays.toString(mac1) + ")");

		byte[] mac2Calculated = new byte[16];
		if (!Arrays.equals(mac2, mac2Calculated))
			throw new BadPaddingException("Invalid MAC2 (expected " + Arrays.toString(mac2Calculated) + " but got " + Arrays.toString(mac2) + ")");
	}


	@Override
	public InetSocketAddress originAddress() {
		return sender;
	}
	@Override
	public long length() {
		return ResponsePacket.HEADER_LAYOUT.byteSize();
	}
}
