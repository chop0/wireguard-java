package ax.xz.wireguard.device.message.initiation;

import ax.xz.wireguard.device.message.PacketElement;
import ax.xz.wireguard.noise.crypto.Blake2s;
import ax.xz.wireguard.noise.crypto.Crypto;
import ax.xz.wireguard.noise.keys.NoisePublicKey;

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
public abstract sealed class InitiationPacket extends PacketElement permits IncomingInitiation, OutgoingInitiation {
	public static final byte TYPE = 1;
	static final StructLayout HEADER_LAYOUT = structLayout(
		JAVA_BYTE.withName("message_type"),
		paddingLayout(3),
		JAVA_INT.withName("sender_index"),

		sequenceLayout(NoisePublicKey.LENGTH, JAVA_BYTE).withName("unencrypted_ephemeral"),
		sequenceLayout(NoisePublicKey.LENGTH + ChaChaPoly1305Overhead, JAVA_BYTE).withName("encrypted_static"),
		sequenceLayout(Crypto.TIMESTAMP_LENGTH + ChaChaPoly1305Overhead, JAVA_BYTE).withName("encrypted_timestamp"),

		sequenceLayout(16, JAVA_BYTE).withName("mac1"),
		sequenceLayout(16, JAVA_BYTE).withName("mac2")
	);
	static final VarHandle MESSAGE_TYPE = HEADER_LAYOUT.varHandle(groupElement("message_type"));
	static final VarHandle SENDER_INDEX = HEADER_LAYOUT.varHandle(groupElement("sender_index"));

	static final MethodHandle UNENCRYPTED_EPHEMERAL = HEADER_LAYOUT.sliceHandle(groupElement("unencrypted_ephemeral"));
	static final MethodHandle ENCRYPTED_STATIC = HEADER_LAYOUT.sliceHandle(groupElement("encrypted_static"));
	static final MethodHandle ENCRYPTED_TIMESTAMP = HEADER_LAYOUT.sliceHandle(groupElement("encrypted_timestamp"));

	static final MethodHandle MAC1 = HEADER_LAYOUT.sliceHandle(groupElement("mac1"));
	static final MethodHandle MAC2 = HEADER_LAYOUT.sliceHandle(groupElement("mac2"));

	private static final byte[] WG_LABEL_MAC1 = "mac1----".getBytes(StandardCharsets.UTF_8);
	private static final byte[] WG_LABEL_COOKIE = "cookie--".getBytes(StandardCharsets.UTF_8);

	protected final MemorySegment header;

	protected InitiationPacket(PacketElement data) {
		super(data);
		this.header = backing().asSlice(0, HEADER_LAYOUT);
	}

	public int senderIndex() {
		return (int) SENDER_INDEX.get(header);
	}

	public NoisePublicKey ephemeral() {
		try {
			return new NoisePublicKey(((MemorySegment) UNENCRYPTED_EPHEMERAL.invokeExact(header)).toArray(JAVA_BYTE));
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	public byte[] encryptedStatic() {
		try {
			return ((MemorySegment) ENCRYPTED_STATIC.invokeExact(header)).toArray(JAVA_BYTE);
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	public byte[] encryptedTimestamp() {
		try {
			return ((MemorySegment) ENCRYPTED_TIMESTAMP.invokeExact(header)).toArray(JAVA_BYTE);
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	public byte[] mac1() {
		try {
			return ((MemorySegment) MAC1.invokeExact(header)).toArray(JAVA_BYTE);
		} catch (Throwable e) {
			throw new Error(e);
		}
	}

	public byte[] mac2() {
		try {
			return ((MemorySegment) MAC2.invokeExact(header)).toArray(JAVA_BYTE);
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
