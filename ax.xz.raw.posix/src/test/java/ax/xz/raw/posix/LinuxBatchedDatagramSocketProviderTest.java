package ax.xz.raw.posix;

import ax.xz.raw.spi.BatchedDatagramSocket;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class LinuxBatchedDatagramSocketProviderTest {
	@Test
	void testSend() throws IOException, InterruptedException {
		try (var arena = Arena.ofConfined();
			 var s1 = new LinuxBatchedDatagramSocketProvider().open();
			 var s2 = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 1234))) {
			var sendData = new byte[]{0, 1, 2, 3};
			var receiveData = new byte[sendData.length];

			s1.send(Stream.of(new BatchedDatagramSocket.Packet((InetSocketAddress) s2.getLocalAddress(), arena.allocate(sendData.length).copyFrom(MemorySegment.ofArray(sendData)))));

			s2.receive(ByteBuffer.wrap(receiveData));

			assertArrayEquals(sendData, receiveData);
		}
	}
}