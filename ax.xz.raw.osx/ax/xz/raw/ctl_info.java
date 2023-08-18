package ax.xz.raw;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static ax.xz.raw.OSXSyscalls.C_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;

class ctl_info {
	private static final long MAX_KCTL_NAME = 96;
	private static final MemoryLayout ctlInfo = MemoryLayout.structLayout(JAVA_INT.withName("ctl_id"), MemoryLayout.sequenceLayout(MAX_KCTL_NAME, C_CHAR).withName("ctl_name"));

	private static final VarHandle ctl_id$VH = ctlInfo.varHandle(MemoryLayout.PathElement.groupElement("ctl_id"));
	private static final MethodHandle ctl_name$VH = ctlInfo.sliceHandle(MemoryLayout.PathElement.groupElement("ctl_name"));

	private final MemorySegment seg;

	ctl_info(MemorySegment seg) {
		this.seg = seg;
	}

	static ctl_info allocate(Arena arena) {
		return new ctl_info(arena.allocate(ctlInfo));
	}

	int ctlId() {
		return (int) ctl_id$VH.get(seg);
	}

	void setCtlId(int ctlId) {
		ctl_id$VH.set(seg, ctlId);
	}

	String ctlName() {
		try {
			return ((MemorySegment) ctl_name$VH.invokeExact(seg)).getUtf8String(0);
		} catch (Throwable e) {
			throw new Error("unreachable", e);
		}
	}

	void setCtlName(String ctlName) {
		try {
			((MemorySegment) ctl_name$VH.invokeExact(seg)).setUtf8String(0, ctlName);
		} catch (Throwable e) {
			throw new Error("unreachable", e);
		}
	}

	public MemorySegment getSeg() {
		return seg;
	}
}
