package ax.xz.wireguard.iptables;

import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.spi.PeerChannel;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.Arrays;
import java.util.Optional;

public class IptablesChannel implements PeerChannel {
	private final DatagramChannel channel;

	private byte packetType;
	private int receiverIndex;

	public IptablesChannel(NoisePublicKey remoteKey, byte packetType) throws IOException {
		channel = DatagramChannel.open().bind(null);
	}

	@Override
	public InetSocketAddress receive(ByteBuffer buffer) throws IOException {
		return (InetSocketAddress) channel.receive(buffer);
	}

	@Override
	public void send(ByteBuffer buffer) throws IOException {

	}

	@Override
	public void bind(byte packetType, int receiverIndex) {

	}

	@Override
	public void connect(InetSocketAddress remote) {

	}

	@Override
	public boolean supportsParallelReceive() {
		return false;
	}

	@Override
	public void close() throws Exception {

	}

	sealed interface silly<T extends silly> {
		record layer<T extends silly>(T t) implements silly<T> {}
		record leaf() implements silly<leaf> {}
	}
	
	silly.layer<
}
