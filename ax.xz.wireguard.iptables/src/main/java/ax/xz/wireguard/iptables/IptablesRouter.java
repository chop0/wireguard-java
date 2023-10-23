package ax.xz.wireguard.iptables;

import ax.xz.wireguard.noise.keys.NoisePublicKey;
import ax.xz.wireguard.spi.WireguardRouter;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

public class IptablesRouter<T> implements WireguardRouter {
	private static final System.Logger logger = System.getLogger(IptablesRouter.class.getName());

	private final ReentrantLock lock = new ReentrantLock();

	private final HashMap<NoisePublicKey, Integer> peerIndices = new HashMap<>();

	private final ArrayList<RoutingEntry<T>> routingList = new ArrayList<>();
	private final LinkedList<Integer> freeIndices = new LinkedList<>();

	private InitiationHandler fallbackPacketHandler = i -> logger.log(System.Logger.Level.DEBUG, "Fallback handler not configured: " + i);
	private final DatagramChannel fallbackSocket;

	public IptablesRouter() throws IOException {
		this.fallbackSocket = DatagramChannel.open();
	}

	@Override
	public void bind(InetSocketAddress address) throws IOException {
		fallbackSocket.bind(address);
	}
	@Override
	public void send(ByteBuffer buffer, InetSocketAddress address) throws IOException {
		fallbackSocket.send(buffer, address);
	}

	@Override
	public int shuffleIndex(NoisePublicKey remoteKey) {
		lock.lock();
		try {
			RoutingEntry<T> entry;
			if (peerIndices.containsKey(remoteKey)) {
				entry = removeEntry(peerIndices.get(remoteKey));
			} else {
				entry = new RoutingEntry<>(new HashSet<>(), DatagramChannel.open(), null);
			}

			var newIndex = allocateIndex();

			putAtIndex(remoteKey, newIndex, entry);

			return newIndex;
		} finally {
			lock.unlock();
		}
	}

	private void putAtIndex(NoisePublicKey remoteKey, int newIndex, RoutingEntry<T> entry) {
		peerIndices.put(remoteKey, newIndex);
		routingList.set(newIndex, entry);
	}

	private RoutingEntry<T> removeEntry(int index) {
		RoutingEntry<T> entry;
		freeIndices.addLast(index);
		entry = routingList.set(index, null);
		return entry;
	}

	private int allocateIndex() {
		int newIndex;
		if (freeIndices.isEmpty()) {
			newIndex = routingList.size();
			routingList.add(null);
		} else {
			newIndex = freeIndices.removeFirst();
		}

		return newIndex;
	}

	@Override
	public void close() throws InterruptedException {

	}

	@Override
	public IptablesChannel openChannel(NoisePublicKey remoteKey, byte packetType) throws IOException {
		return new IptablesChannel(remoteKey, packetType);
	}

	@Override
	public void configureInitiationHandler(InitiationHandler handler) {
		this.fallbackPacketHandler = handler;
	}

	private record RoutingEntry<T>(Set<IptablesChannel> channels, DatagramChannel sendSocket, T associatedData) {}
}
