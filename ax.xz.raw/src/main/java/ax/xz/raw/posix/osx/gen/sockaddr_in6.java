// Generated by jextract

package ax.xz.raw.posix.osx.gen;

import java.lang.invoke.*;
import java.lang.foreign.*;
import java.nio.ByteOrder;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

import static java.lang.foreign.ValueLayout.*;
import static java.lang.foreign.MemoryLayout.PathElement.*;

/**
 * {@snippet lang=c :
 * struct sockaddr_in6 {
 *     __uint8_t sin6_len;
 *     sa_family_t sin6_family;
 *     in_port_t sin6_port;
 *     __uint32_t sin6_flowinfo;
 *     struct in6_addr sin6_addr;
 *     __uint32_t sin6_scope_id;
 * }
 * }
 */
public class sockaddr_in6 {

    sockaddr_in6() {
        // Should not be called directly
    }

    private static final GroupLayout $LAYOUT = MemoryLayout.structLayout(
        osx_tun_h.C_CHAR.withName("sin6_len"),
        osx_tun_h.C_CHAR.withName("sin6_family"),
        osx_tun_h.C_SHORT.withName("sin6_port"),
        osx_tun_h.C_INT.withName("sin6_flowinfo"),
        in6_addr.layout().withName("sin6_addr"),
        osx_tun_h.C_INT.withName("sin6_scope_id")
    ).withName("sockaddr_in6");

    /**
     * The layout of this struct
     */
    public static final GroupLayout layout() {
        return $LAYOUT;
    }

    private static final OfByte sin6_len$LAYOUT = (OfByte)$LAYOUT.select(groupElement("sin6_len"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __uint8_t sin6_len
     * }
     */
    public static final OfByte sin6_len$layout() {
        return sin6_len$LAYOUT;
    }

    private static final long sin6_len$OFFSET = 0;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __uint8_t sin6_len
     * }
     */
    public static final long sin6_len$offset() {
        return sin6_len$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __uint8_t sin6_len
     * }
     */
    public static byte sin6_len(MemorySegment struct) {
        return struct.get(sin6_len$LAYOUT, sin6_len$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __uint8_t sin6_len
     * }
     */
    public static void sin6_len(MemorySegment struct, byte fieldValue) {
        struct.set(sin6_len$LAYOUT, sin6_len$OFFSET, fieldValue);
    }

    private static final OfByte sin6_family$LAYOUT = (OfByte)$LAYOUT.select(groupElement("sin6_family"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * sa_family_t sin6_family
     * }
     */
    public static final OfByte sin6_family$layout() {
        return sin6_family$LAYOUT;
    }

    private static final long sin6_family$OFFSET = 1;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * sa_family_t sin6_family
     * }
     */
    public static final long sin6_family$offset() {
        return sin6_family$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * sa_family_t sin6_family
     * }
     */
    public static byte sin6_family(MemorySegment struct) {
        return struct.get(sin6_family$LAYOUT, sin6_family$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * sa_family_t sin6_family
     * }
     */
    public static void sin6_family(MemorySegment struct, byte fieldValue) {
        struct.set(sin6_family$LAYOUT, sin6_family$OFFSET, fieldValue);
    }

    private static final OfShort sin6_port$LAYOUT = (OfShort)$LAYOUT.select(groupElement("sin6_port"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * in_port_t sin6_port
     * }
     */
    public static final OfShort sin6_port$layout() {
        return sin6_port$LAYOUT;
    }

    private static final long sin6_port$OFFSET = 2;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * in_port_t sin6_port
     * }
     */
    public static final long sin6_port$offset() {
        return sin6_port$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * in_port_t sin6_port
     * }
     */
    public static short sin6_port(MemorySegment struct) {
        return struct.get(sin6_port$LAYOUT, sin6_port$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * in_port_t sin6_port
     * }
     */
    public static void sin6_port(MemorySegment struct, short fieldValue) {
        struct.set(sin6_port$LAYOUT, sin6_port$OFFSET, fieldValue);
    }

    private static final OfInt sin6_flowinfo$LAYOUT = (OfInt)$LAYOUT.select(groupElement("sin6_flowinfo"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __uint32_t sin6_flowinfo
     * }
     */
    public static final OfInt sin6_flowinfo$layout() {
        return sin6_flowinfo$LAYOUT;
    }

    private static final long sin6_flowinfo$OFFSET = 4;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __uint32_t sin6_flowinfo
     * }
     */
    public static final long sin6_flowinfo$offset() {
        return sin6_flowinfo$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __uint32_t sin6_flowinfo
     * }
     */
    public static int sin6_flowinfo(MemorySegment struct) {
        return struct.get(sin6_flowinfo$LAYOUT, sin6_flowinfo$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __uint32_t sin6_flowinfo
     * }
     */
    public static void sin6_flowinfo(MemorySegment struct, int fieldValue) {
        struct.set(sin6_flowinfo$LAYOUT, sin6_flowinfo$OFFSET, fieldValue);
    }

    private static final GroupLayout sin6_addr$LAYOUT = (GroupLayout)$LAYOUT.select(groupElement("sin6_addr"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * struct in6_addr sin6_addr
     * }
     */
    public static final GroupLayout sin6_addr$layout() {
        return sin6_addr$LAYOUT;
    }

    private static final long sin6_addr$OFFSET = 8;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * struct in6_addr sin6_addr
     * }
     */
    public static final long sin6_addr$offset() {
        return sin6_addr$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * struct in6_addr sin6_addr
     * }
     */
    public static MemorySegment sin6_addr(MemorySegment struct) {
        return struct.asSlice(sin6_addr$OFFSET, sin6_addr$LAYOUT.byteSize());
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * struct in6_addr sin6_addr
     * }
     */
    public static void sin6_addr(MemorySegment struct, MemorySegment fieldValue) {
        MemorySegment.copy(fieldValue, 0L, struct, sin6_addr$OFFSET, sin6_addr$LAYOUT.byteSize());
    }

    private static final OfInt sin6_scope_id$LAYOUT = (OfInt)$LAYOUT.select(groupElement("sin6_scope_id"));

    /**
     * Layout for field:
     * {@snippet lang=c :
     * __uint32_t sin6_scope_id
     * }
     */
    public static final OfInt sin6_scope_id$layout() {
        return sin6_scope_id$LAYOUT;
    }

    private static final long sin6_scope_id$OFFSET = 24;

    /**
     * Offset for field:
     * {@snippet lang=c :
     * __uint32_t sin6_scope_id
     * }
     */
    public static final long sin6_scope_id$offset() {
        return sin6_scope_id$OFFSET;
    }

    /**
     * Getter for field:
     * {@snippet lang=c :
     * __uint32_t sin6_scope_id
     * }
     */
    public static int sin6_scope_id(MemorySegment struct) {
        return struct.get(sin6_scope_id$LAYOUT, sin6_scope_id$OFFSET);
    }

    /**
     * Setter for field:
     * {@snippet lang=c :
     * __uint32_t sin6_scope_id
     * }
     */
    public static void sin6_scope_id(MemorySegment struct, int fieldValue) {
        struct.set(sin6_scope_id$LAYOUT, sin6_scope_id$OFFSET, fieldValue);
    }

    /**
     * Obtains a slice of {@code arrayParam} which selects the array element at {@code index}.
     * The returned segment has address {@code arrayParam.address() + index * layout().byteSize()}
     */
    public static MemorySegment asSlice(MemorySegment array, long index) {
        return array.asSlice(layout().byteSize() * index);
    }

    /**
     * The size (in bytes) of this struct
     */
    public static long sizeof() { return layout().byteSize(); }

    /**
     * Allocate a segment of size {@code layout().byteSize()} using {@code allocator}
     */
    public static MemorySegment allocate(SegmentAllocator allocator) {
        return allocator.allocate(layout());
    }

    /**
     * Allocate an array of size {@code elementCount} using {@code allocator}.
     * The returned segment has size {@code elementCount * layout().byteSize()}.
     */
    public static MemorySegment allocateArray(long elementCount, SegmentAllocator allocator) {
        return allocator.allocate(MemoryLayout.sequenceLayout(elementCount, layout()));
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction) (if any).
     * The returned segment has size {@code layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, Arena arena, Consumer<MemorySegment> cleanup) {
        return reinterpret(addr, 1, arena, cleanup);
    }

    /**
     * Reinterprets {@code addr} using target {@code arena} and {@code cleanupAction) (if any).
     * The returned segment has size {@code elementCount * layout().byteSize()}
     */
    public static MemorySegment reinterpret(MemorySegment addr, long elementCount, Arena arena, Consumer<MemorySegment> cleanup) {
        return addr.reinterpret(layout().byteSize() * elementCount, arena, cleanup);
    }
}

