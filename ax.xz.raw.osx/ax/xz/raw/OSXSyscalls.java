package ax.xz.raw;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.util.concurrent.Callable;

import static java.lang.foreign.MemoryLayout.PathElement.groupElement;
import static java.lang.foreign.MemoryLayout.PathElement.sequenceElement;
import static java.lang.foreign.ValueLayout.*;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.util.Objects.requireNonNull;

class OSXSyscalls {
	public static final AddressLayout C_POINTER = ADDRESS
			.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE));
	public static final MemoryLayout C_CHAR = JAVA_BYTE;

	private static final MethodHandle read, readv, write, writev, close, socket, ioctl, connect, strerror, setsockopt;
	private static final VarHandle errno;

	static final int AF_SYSTEM = 32;
	static final int PF_SYSTEM = AF_SYSTEM;
	static final int AF_SYS_CONTROL = 2;
	static final int AF_INET = 2;
	static final int AF_INET6 = 10;
	static final int SOCK_RAW = 3;
	static final int IPPROTO_RAW = 255;
	static final int IPPROTO_IP = 0;
	static final int IPPROTO_IPV6 = 41;
	static final int IP_HDRINCL = 2;

	static final int SOCK_DGRAM = 2;
	static final int SYSPROTO_CONTROL = 2;
	private static final long CTLIOCGINFO = 3227799043L;

	static {
		if (!System.getProperty("os.name").equals("Mac OS X")) {
			throw new IllegalStateException("OSXRawSocket can only be used on Mac OS X");
		}

		read = getLibcFunction("read", FunctionDescriptor.of(JAVA_INT, JAVA_INT, C_POINTER, JAVA_INT));
		readv = getLibcFunction("readv", FunctionDescriptor.of(JAVA_INT, JAVA_INT, C_POINTER, JAVA_INT));
		write = getLibcFunction("write", FunctionDescriptor.of(JAVA_INT, JAVA_INT, C_POINTER, JAVA_INT));
		writev = getLibcFunction("writev", FunctionDescriptor.of(JAVA_INT, JAVA_INT, C_POINTER, JAVA_INT));
		close = getLibcFunction("close", FunctionDescriptor.of(JAVA_INT, JAVA_INT));
		socket = getLibcFunction("socket", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT));
		ioctl = getLibcFunction("ioctl", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, C_POINTER), Linker.Option.firstVariadicArg(2));
		connect = getLibcFunction("connect", FunctionDescriptor.of(JAVA_INT, JAVA_INT, C_POINTER, JAVA_INT));
		strerror = getLibcFunction("strerror", FunctionDescriptor.of(C_POINTER, JAVA_INT));
		setsockopt = getLibcFunction("setsockopt", FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, C_POINTER, JAVA_INT));

		var cFunctionPointer = ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_INT));
		try {
			var __error = (MemorySegment)getLibcFunction("__error", FunctionDescriptor.of(cFunctionPointer)).invokeExact();
			errno = MethodHandles.insertCoordinates(MethodHandles.memorySegmentViewVarHandle(JAVA_INT), 0, __error, 0);
		} catch (Throwable e) {
			throw new RuntimeException(e);
		}
	}

	private static MethodHandle getLibcFunction(String name, FunctionDescriptor descriptor, Linker.Option... options) {
		return Linker.nativeLinker().defaultLookup()
				.find(name)
				.map(ms -> Linker.nativeLinker().downcallHandle(ms, descriptor, options))
				.orElseThrow();
	}

	private static MemorySegment bufferAddress(ByteBuffer buffer) {
		requireNonNull(buffer);
		return MemorySegment.ofBuffer(buffer); // TODO:  maybe make sure this works with weird views
	}

	static void read(int fd, ByteBuffer buffer) throws IOException {
		var result = invokeLibcFunction(read, fd, bufferAddress(buffer), buffer.remaining());

		buffer.position(buffer.position() + result);
	}

	static void write(int fd, ByteBuffer buffer) throws IOException {
		var result = invokeLibcFunction(write, fd, bufferAddress(buffer), buffer.remaining());

		buffer.position(buffer.position() + result);
	}


	interface IOVec {
		MemoryLayout LAYOUT = MemoryLayout.structLayout(
				C_POINTER.withName("iov_base"),
				JAVA_LONG.withName("iov_len")
		);
		AddressLayout POINTER = ADDRESS.withTargetLayout(LAYOUT);

		VarHandle iov_base$ = LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("iov_base"));
		VarHandle iov_len$ = LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("iov_len"));
	}

	static void writev(int fd, ByteBuffer... buffers) throws IOException {
		try (var arena = Arena.ofConfined()) {
			var layout = MemoryLayout.sequenceLayout(buffers.length, IOVec.LAYOUT);
			var iov = arena.allocate(layout);

			for (int i = 0; i < buffers.length; i++) {
				var item = iov.asSlice(i * IOVec.LAYOUT.byteSize(), IOVec.LAYOUT);
				IOVec.iov_base$.set(item, bufferAddress(buffers[i]));
				IOVec.iov_len$.set(item, buffers[i].remaining());
			}

			var result = invokeLibcFunction(writev, fd, iov, buffers.length);
			for (int i = 0; i < buffers.length && result > 0; i++) {
				int n = Math.min(result, buffers[i].remaining());
				buffers[i].position(buffers[i].position() + n);
				result -= n;
			}
		}
	}

	static void readv(int fd, ByteBuffer... buffers) throws IOException {
		try (var arena = Arena.ofConfined()) {
			var layout = MemoryLayout.sequenceLayout(buffers.length, IOVec.LAYOUT);
			var iov = arena.allocate(layout);

			for (int i = 0; i < buffers.length; i++) {
				var item = iov.asSlice(i * IOVec.LAYOUT.byteSize(), IOVec.LAYOUT);

				IOVec.iov_base$.set(item, bufferAddress(buffers[i]));
				IOVec.iov_len$.set(item, buffers[i].remaining());
			}

			var result = invokeLibcFunction(readv, fd, iov, buffers.length);
			for (int i = 0; i < buffers.length && result > 0; i++) {
				int n = Math.min(result, buffers[i].remaining());
				buffers[i].position(buffers[i].position() + n);
				result -= n;
			}
		}
	}

	static void close(int fd) throws IOException {
		invokeLibcFunction(close, fd);
	}

	static int socket(int domain, int type, int protocol) throws IOException {
		return invokeLibcFunction(socket, domain, type, protocol);
	}

	static void ioctl(int fd, long request, MemorySegment buffer) throws IOException {
		invokeLibcFunction(ioctl, fd, request, buffer);
	}

	static void connect(int fd, MemorySegment address) throws IOException {
		invokeLibcFunction(connect, fd, address, (int)address.byteSize());
	}

	static void setsockopt(int fd, int level, int option, MemorySegment value) throws IOException {
		invokeLibcFunction(setsockopt, fd, level, option, value, (int)value.byteSize());
	}

	static String strerror(int errno) throws IOException {
		try {
			var result = (MemorySegment) strerror.invoke(errno);
			return result.getUtf8String(0);
		} catch (Throwable e) {
			throw new Error("unreachable", e);
		}
	}

	static int errno() throws IOException {
		try {
			return (int) errno.get();
		} catch (Throwable e) {
			throw new Error("unreachable", e);
		}
	}

	private static int invokeLibcFunction(MethodHandle method, Object... args) throws IOException {
		int result;

		try {
			result = (int) method.invokeWithArguments(args);
		} catch (Throwable e) {
			throw new Error("unreachable", e);
		}

		if (result < 0) {
			throw new IOException(strerror(errno()));
		}
		return result;
	}

	static int getControlID(String name) throws IOException {
		int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

		try (var arena = Arena.ofConfined()) {
			var ctl_info_ = ctl_info.allocate(arena);
			ctl_info_.setCtlName(name);

			ioctl(fd, CTLIOCGINFO, ctl_info_.getSeg());
			return ctl_info_.ctlId();
		} finally {
			close(fd);
		}
	}
}
