package ax.xz.wireguard.util;

import java.lang.foreign.MemorySegment;
import java.net.InetAddress;
import java.net.UnknownHostException;

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

public class IPFilter {
	private final Node root4 = new Node();
	private final Node root6 = new Node();

	private static class Node {
		Node[] children = new Node[2];
		boolean isEndOfSubnet;
	}

	private boolean getBit(byte[] bytes, int position) {
		int bytePosition = position / 8;
		int bitPosition = position % 8;
		return ((bytes[bytePosition] >>> (7 - bitPosition)) & 1) != 0;
	}

	private boolean getBit(MemorySegment bytes, int position) {
		int bytePosition = position / 8;
		int bitPosition = position % 8;
		return ((bytes.get(JAVA_BYTE, bytePosition) >>> (7 - bitPosition)) & 1) != 0;
	}

	public void insert(InetAddress subnet, int prefixLength) {
		byte[] bytes = subnet.getAddress();
		var node = bytes.length == 4 ? root4 : root6;

		for (int i = 0; i < prefixLength; i++) {
			int bit = getBit(bytes, i) ? 1 : 0;
			if (node.children[bit] == null) {
				node.children[bit] = new Node();
			}
			node = node.children[bit];
		}
		node.isEndOfSubnet = true;
	}

	/**
	 * Returns true if the given IP address is in the filter.
	 * @param ipBytes the IP address to check
	 * @return true if the given IP address is in the filter
	 */
	public boolean search(MemorySegment ipBytes) {
		var node = ipBytes.byteSize() == 4 ? root4 : root6;

		boolean found = false;
		for (int i = 0; i < ipBytes.byteSize() * 8; i++) {
			int bit = getBit(ipBytes, i) ? 1 : 0;
			node = node.children[bit];
			if (node == null) break;
			if (node.isEndOfSubnet) found = true;
		}
		return found;
	}

	public boolean search(InetAddress address) {
		return search(MemorySegment.ofArray(address.getAddress()));
	}

	public static IPFilter allowingAll() {
		var filter = new IPFilter();
		try {
			filter.insert(InetAddress.getByName("0.0.0.0"), 32);
			filter.insert(InetAddress.getByName("::"), 128);
		} catch (UnknownHostException e) {
			throw new Error(e);
		}

		return filter;
	}

	public static void main(String[] args) {
		try {
			IPFilter tree = new IPFilter();
			tree.insert(InetAddress.getByName("192.168.1.0"), 24);
			tree.insert(InetAddress.getByName("2001:db8::"), 32);

			System.out.println(tree.search(InetAddress.getByName("192.168.1.55"))); // should return true
			System.out.println(tree.search(InetAddress.getByName("192.168.2.1"))); // should return false
			System.out.println(tree.search(InetAddress.getByName("2001:db8::abcd"))); // should return true
			System.out.println(tree.search(InetAddress.getByName("2001:db9::abcd"))); // should return false

		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
	}

}

