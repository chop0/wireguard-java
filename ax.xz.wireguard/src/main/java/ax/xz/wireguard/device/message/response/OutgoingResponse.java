package ax.xz.wireguard.device.message.response;

import ax.xz.wireguard.device.message.OutgoingPeerPacket;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;

public final class OutgoingResponse extends ResponsePacket implements OutgoingPeerPacket {

	public OutgoingResponse(Uninitialised data, int senderIndex, int receiverIndex, NoisePublicKey ephemeral, byte[] encryptedNothing, NoisePublicKey initiatorKey) {
		super(data);

		ResponsePacket.MESSAGE_TYPE.set(header, ResponsePacket.TYPE);
		ResponsePacket.SENDER_INDEX.set(header, senderIndex);
		ResponsePacket.RECEIVER_INDEX.set(header, receiverIndex);

		try {
			((MemorySegment) ResponsePacket.UNENCRYPTED_EPHEMERAL.invokeExact(header)).copyFrom(MemorySegment.ofArray(ephemeral.data()));
			((MemorySegment) ResponsePacket.ENCRYPTED_NOTHING.invokeExact(header)).copyFrom(MemorySegment.ofArray(encryptedNothing));

			((MemorySegment) ResponsePacket.MAC1.invokeExact(header)).copyFrom(MemorySegment.ofArray(calculateMac1(initiatorKey)));
			((MemorySegment) ResponsePacket.MAC2.invokeExact(header)).fill((byte) 0); // TODO:  implement cookie
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	@Override
	public long length() {
		return HEADER_LAYOUT.byteSize();
	}

	@Override
	public MemorySegment transmissiblePacket() {
		return backing().asSlice(0, length());
	}
}
