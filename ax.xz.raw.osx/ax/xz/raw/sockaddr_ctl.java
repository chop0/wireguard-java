package ax.xz.raw;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static ax.xz.raw.OSXSyscalls.C_CHAR;
import static java.lang.foreign.ValueLayout.*;

/*!
 *       @struct sockaddr_ctl
 *       @discussion The controller address structure is used to establish
 *               contact between a user client and a kernel controller. The
 *               sc_id/sc_unit uniquely identify each controller. sc_id is a
 *               unique identifier assigned to the controller. The identifier can
 *               be assigned by the system at registration time or be a 32-bit
 *               creator code obtained from Apple Computer. sc_unit is a unit
 *               number for this sc_id, and is privately used by the kernel
 *               controller to identify several instances of the controller.
 *       @field sc_len The length of the structure.
 *       @field sc_family AF_SYSTEM.
 *       @field ss_sysaddr AF_SYS_KERNCONTROL.
 *       @field sc_id Controller unique identifier.
 *       @field sc_unit Kernel controller private unit number.
 *       @field sc_reserved Reserved, must be set to zero.

struct sockaddr_ctl {
        u_char      sc_len;     // depends on size of bundle ID string
        u_char      sc_family;  // AF_SYSTEM
				u_int16_t   ss_sysaddr; // AF_SYS_KERNCONTROL
				u_int32_t   sc_id;      // Controller unique identifier
				u_int32_t   sc_unit;    // Developer private unit number
				u_int32_t   sc_reserved[5];
				};
 */
class sockaddr_ctl {
	private static final MemoryLayout sockaddrCtl = MemoryLayout.structLayout(
			JAVA_BYTE.withName("sc_len"),
			JAVA_BYTE.withName("sc_family"),

			JAVA_SHORT.withName("ss_sysaddr"),
			JAVA_INT.withName("sc_id"),
			JAVA_INT.withName("sc_unit"),

			MemoryLayout.sequenceLayout(5, JAVA_INT).withName("sc_reserved")
	);

	private static final VarHandle sc_len$VH = sockaddrCtl.varHandle(MemoryLayout.PathElement.groupElement("sc_len"));
	private static final VarHandle sc_family$VH = sockaddrCtl.varHandle(MemoryLayout.PathElement.groupElement("sc_family"));
	private static final VarHandle ss_sysaddr$VH = sockaddrCtl.varHandle(MemoryLayout.PathElement.groupElement("ss_sysaddr"));
	private static final VarHandle sc_id$VH = sockaddrCtl.varHandle(MemoryLayout.PathElement.groupElement("sc_id"));
	private static final VarHandle sc_unit$VH = sockaddrCtl.varHandle(MemoryLayout.PathElement.groupElement("sc_unit"));

	private final MemorySegment seg;

	sockaddr_ctl(MemorySegment seg) {
		this.seg = seg;
	}

	static sockaddr_ctl allocate() {
		return new sockaddr_ctl(Arena.ofAuto().allocate(sockaddrCtl));
	}

	int scLen() {
		return (((byte) sc_len$VH.get(seg)) & 0xFF);
	}

	void setScLen(int scLen) {
		if (scLen < 0 || scLen > 255) {
			throw new IllegalArgumentException("scLen must be between 0 and 255");
		}

		sc_len$VH.set(seg, (byte) scLen);
	}

	int scFamily() {
		return (((byte) sc_family$VH.get(seg)) & 0xFF);
	}

	void setScFamily(int scFamily) {
		if (scFamily < 0 || scFamily > 255) {
			throw new IllegalArgumentException("scFamily must be between 0 and 255");
		}

		sc_family$VH.set(seg, (byte) scFamily);
	}

	int ssSysaddr() {
		return ((short)ss_sysaddr$VH.get(seg) & 0xFFFF);
	}

	void setSsSysaddr(int ssSysaddr) {
		if (ssSysaddr < 0 || ssSysaddr > 65535) {
			throw new IllegalArgumentException("ssSysaddr must be between 0 and 65535");
		}

		ss_sysaddr$VH.set(seg, (short) ssSysaddr);
	}

	long scId() {
		return ((int) sc_id$VH.get(seg) & 0xFFFFFFFFL);
	}

	void setScId(long scId) {
		if (scId < 0 || scId > (1L << 32) - 1) {
			throw new IllegalArgumentException("scId must be between 0 and 4294967295");
		}

		sc_id$VH.set(seg, (int) scId);
	}

	long scUnit() {
		return ((int) sc_unit$VH.get(seg) & 0xFFFFFFFFL);
	}

	void setScUnit(long scUnit) {
		if (scUnit < 0 || scUnit > (1L << 32) - 1) {
			throw new IllegalArgumentException("scUnit must be between 0 and 4294967295");
		}

		sc_unit$VH.set(seg, (int) scUnit);
	}

	public MemorySegment getSeg() {
		return seg;
	}
}
