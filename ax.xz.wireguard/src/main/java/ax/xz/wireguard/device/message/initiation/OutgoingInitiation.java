package ax.xz.wireguard.device.message.initiation;

import ax.xz.wireguard.device.message.OutgoingPeerPacket;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;

/**
 * msg = handshake_initiation {
 * u8 message_type
 * u8 reserved_zero[3]
 * u32 sender_index
 * u8 unencrypted_ephemeral[32]
 * u8 encrypted_static[AEAD_LEN(32)]
 * u8 encrypted_timestamp[AEAD_LEN(12)]
 * u8 mac1[16]
 * u8 mac2[16]
 * }
 */
public final class OutgoingInitiation extends InitiationPacket implements OutgoingPeerPacket {
	public OutgoingInitiation(Uninitialised data, int senderIndex, NoisePublicKey ephemeral, byte[] encryptedStatic, byte[] encryptedTimestamp, NoisePublicKey responderKey) {
		super(data);

		InitiationPacket.MESSAGE_TYPE.set(header, InitiationPacket.TYPE);
		InitiationPacket.SENDER_INDEX.set(header, senderIndex);

		try {
			((MemorySegment) InitiationPacket.UNENCRYPTED_EPHEMERAL.invokeExact(header)).copyFrom(MemorySegment.ofArray(ephemeral.data()));
			((MemorySegment) InitiationPacket.ENCRYPTED_STATIC.invokeExact(header)).copyFrom(MemorySegment.ofArray(encryptedStatic));
			((MemorySegment) InitiationPacket.ENCRYPTED_TIMESTAMP.invokeExact(header)).copyFrom(MemorySegment.ofArray(encryptedTimestamp));

			((MemorySegment) MAC1.invokeExact(header)).copyFrom(MemorySegment.ofArray(calculateMac1(responderKey)));
			((MemorySegment) MAC2.invokeExact(header)).fill((byte) 0); // TODO:  implement cookie
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	@Override
	public MemorySegment transmissiblePacket() {
		return backing().asSlice(0, length());
	}

	@Override
	public long length() {
		return HEADER_LAYOUT.byteSize();
	}
}
