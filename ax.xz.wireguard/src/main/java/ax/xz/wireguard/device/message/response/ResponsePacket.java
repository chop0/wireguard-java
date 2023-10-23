package ax.xz.wireguard.device.message.response;

import ax.xz.wireguard.device.message.PacketElement;
import ax.xz.wireguard.noise.crypto.Blake2s;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;

import static ax.xz.wireguard.noise.crypto.Crypto.ChaChaPoly1305Overhead;
import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.MemoryLayout.*;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * msg = handshake_response {
 * u8 message_type
 * u8 reserved_zero[3]
 * u32 sender_index
 * u32 receiver_index
 * u8 unencrypted_ephemeral[32]
 * u8 encrypted_nothing[AEAD_LEN(0)]
 * u8 mac1[16]
 * u8 mac2[16]
 * }
 */

public abstract sealed class ResponsePacket extends PacketElement permits IncomingResponse, OutgoingResponse {
	public static final byte TYPE = 2;
	static final StructLayout HEADER_LAYOUT = structLayout(
		JAVA_BYTE.withName("message_type"),
		paddingLayout(3),
		JAVA_INT.withName("sender_index"),
		JAVA_INT.withName("receiver_index"),

		sequenceLayout(NoisePublicKey.LENGTH, JAVA_BYTE).withName("unencrypted_ephemeral"),
		sequenceLayout(ChaChaPoly1305Overhead, JAVA_BYTE).withName("encrypted_nothing"),

		sequenceLayout(16, JAVA_BYTE).withName("mac1"),
		sequenceLayout(16, JAVA_BYTE).withName("mac2")
	);
	static final VarHandle MESSAGE_TYPE = HEADER_LAYOUT.varHandle(groupElement("message_type"));

	static final VarHandle SENDER_INDEX = HEADER_LAYOUT.varHandle(groupElement("sender_index"));
	static final VarHandle RECEIVER_INDEX = HEADER_LAYOUT.varHandle(groupElement("receiver_index"));

	static final MethodHandle UNENCRYPTED_EPHEMERAL = HEADER_LAYOUT.sliceHandle(groupElement("unencrypted_ephemeral"));
	static final MethodHandle ENCRYPTED_NOTHING = HEADER_LAYOUT.sliceHandle(groupElement("encrypted_nothing"));

	static final MethodHandle MAC1 = HEADER_LAYOUT.sliceHandle(groupElement("mac1"));
	static final MethodHandle MAC2 = HEADER_LAYOUT.sliceHandle(groupElement("mac2"));

	private static final byte[] WG_LABEL_MAC1 = "mac1----".getBytes(StandardCharsets.UTF_8);
	private static final byte[] WG_LABEL_COOKIE = "cookie--".getBytes(StandardCharsets.UTF_8);

	protected final MemorySegment header;

	protected ResponsePacket(PacketElement data) {
		super(data);
		this.header = backing().asSlice(0, HEADER_LAYOUT);
	}

	public int senderIndex() {
		return (int) ResponsePacket.SENDER_INDEX.get(header);
	}

	public int receiverIndex() {
		return (int) ResponsePacket.RECEIVER_INDEX.get(header);
	}

	public NoisePublicKey ephemeral() {
		try {
			return new NoisePublicKey(((MemorySegment) ResponsePacket.UNENCRYPTED_EPHEMERAL.invokeExact(header)).toArray(JAVA_BYTE));
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	public byte[] encryptedNothing() {
		try {
			return ((MemorySegment) ResponsePacket.ENCRYPTED_NOTHING.invokeExact(header)).toArray(JAVA_BYTE);
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	public byte[] mac1() {
		try {
			return ((MemorySegment) ResponsePacket.MAC1.invokeExact(header)).toArray(JAVA_BYTE);
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	public byte[] mac2() {
		try {
			return ((MemorySegment) ResponsePacket.MAC2.invokeExact(header)).toArray(JAVA_BYTE);
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	protected byte[] calculateMac1(NoisePublicKey initiatorKey) {
		var keyHash = new Blake2s(32);

		keyHash.update(WG_LABEL_MAC1);
		keyHash.update(initiatorKey.data());
		byte[] mac1Key = keyHash.digest();

		var macHash = new Blake2s(128 / 8, mac1Key);
		macHash.update(backing().asSlice(0, HEADER_LAYOUT.byteOffset(groupElement("mac1"))).asByteBuffer());
		return macHash.digest();
	}
}
