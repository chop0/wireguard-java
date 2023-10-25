package ax.xz.raw.posix;

import ax.xz.raw.posix.gen.*;
import ax.xz.raw.spi.BatchedDatagramSocket;
import ax.xz.raw.spi.BatchedDatagramSocketProvider;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static ax.xz.raw.posix.POSIXTunUtils.AF_INET;
import static ax.xz.raw.posix.POSIXTunUtils.AF_INET6;
import static ax.xz.raw.posix.gen.a_h.*;
import static java.lang.foreign.MemoryLayout.unionLayout;

public class LinuxBatchedDatagramSocketProvider implements BatchedDatagramSocketProvider {
	private static final int MAX_MESSAGES = 1024;
	private static final int MAX_IOVECS = 1024;

	private static final MemoryLayout ADDRESS_LAYOUT = unionLayout(sockaddr_in.$LAYOUT(), sockaddr_in6.$LAYOUT());

	@Override
	public BatchedDatagramSocket open() throws IOException {
		return new LinuxBatchedDatagramSocket();
	}

	@Override
	public boolean isAvailable() {
		return System.getProperty("os.name").equals("Linux");
	}

	public static class LinuxBatchedDatagramSocket implements BatchedDatagramSocket {
		private final Set<Integer> fds = ConcurrentHashMap.newKeySet();
		private final ThreadLocal<Integer> fd = ThreadLocal.withInitial(() -> {
			int fd = socket(AF_INET(), SOCK_DGRAM(), 0);
			fds.add(fd);
			return fd;
		});

		private final int receiveFd = socket(AF_INET(), SOCK_DGRAM(), 0);

		@Override
		public void send(Collection<Packet> packets) throws IOException {
			var messages = toMessages(packets);

			int result = sendmmsg(fd.get(), messages.msgs(), messages.i(), 0);
			if (result < 0)
				throw new IOException();
		}

		@Override
		public int receive(Collection<Packet> packets) throws IOException {
			var messages = toMessages(packets);

			int result = recvmmsg(receiveFd, messages.msgs(), messages.i(), MSG_WAITFORONE(), MemorySegment.NULL);
			if (result < 0)
				throw new IOException();

			return result;
		}

		@Override
		public void bind(InetSocketAddress address) throws IOException {
			try (var arena = Arena.ofConfined()) {
				var addr = createAddress(arena.allocate(ADDRESS_LAYOUT), address);
				var result = a_h.bind(receiveFd, addr, (int)addr.byteSize());
				if (result < 0)
					throw new IOException();
			}
		}


		private static MessagesResult toMessages(Collection<Packet> packets) {
			record TL(MemorySegment msgs, MemorySegment iovecs, MemorySegment addresses) {
				TL() {
					this(Arena.ofAuto().allocateArray(mmsghdr.$LAYOUT(), MAX_MESSAGES),
						Arena.ofAuto().allocateArray(iovec.$LAYOUT(), MAX_MESSAGES * MAX_IOVECS), // overcommit
						Arena.ofAuto().allocateArray(ADDRESS_LAYOUT, MAX_MESSAGES));
				}
			}

			class holder {
				static final ThreadLocal<TL> instance = ThreadLocal.withInitial(TL::new);
			}

			var tl = holder.instance.get();

			var msgs = tl.msgs;
			var iovecIterator = tl.iovecs;

			var currentAddressPtr = tl.addresses;

			var iterator = packets.iterator();
			int i;
			for (i = 0; iterator.hasNext(); i++) {
				var packet = iterator.next();

				var msgHeader = mmsghdr.msg_hdr$slice(msgs.asSlice(mmsghdr.sizeof() * i));
				var iovecSlice = iovecIterator.asSlice(i * iovec.sizeof(), packet.segment().length * iovec.sizeof());

				for (int j = 0; j < packet.segment().length; j++) {
					var iovec_ = iovecSlice.asSlice(iovec.$LAYOUT().byteSize() * j, iovec.sizeof());
					var segment = packet.segment()[j];

					iovec.iov_base$set(iovec_, segment);
					iovec.iov_len$set(iovec_, segment.byteSize());
				}

				var addr = createAddress(currentAddressPtr, packet.dst());
				currentAddressPtr = currentAddressPtr.asSlice(addr.byteSize());

				msghdr.msg_name$set(msgHeader, addr);
				msghdr.msg_namelen$set(msgHeader, (int) addr.byteSize());

				msghdr.msg_iov$set(msgHeader, iovecSlice);
				msghdr.msg_iovlen$set(msgHeader, packet.segment().length);
			}
			return new MessagesResult(msgs, i);
		}

		private record MessagesResult(MemorySegment msgs, int i) {
		}

		@Override
		public void close() {
			fds.forEach(fd -> a_h.close(fd));
		}

		private static MemorySegment createAddress(MemorySegment addr, InetSocketAddress socketAddress) {
			var address = socketAddress.getAddress();
			var port = socketAddress.getPort();

			if (address instanceof Inet4Address) {
				sockaddr_in.sin_family$set(addr, (short) AF_INET);
				sockaddr_in.sin_addr$slice(addr).copyFrom(MemorySegment.ofArray(address.getAddress()));
				sockaddr_in.sin_port$set(addr, Short.reverseBytes((short) port));

				return addr.asSlice(0, sockaddr_in.$LAYOUT());
			} else {
				sockaddr_in6.sin6_family$set(addr, (short) AF_INET6);
				sockaddr_in6.sin6_addr$slice(addr).copyFrom(MemorySegment.ofArray(address.getAddress()));
				sockaddr_in6.sin6_port$set(addr, Short.reverseBytes((short) port));

				return addr.asSlice(0, sockaddr_in6.$LAYOUT());
			}
		}
	}
}
