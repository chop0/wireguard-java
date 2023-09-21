package ax.xz.raw.spi;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Set;

public interface Tun extends Closeable, WritableByteChannel, ReadableByteChannel {
	int write(ByteBuffer buffer) throws IOException;
	int read(ByteBuffer buffer) throws IOException;

	/**
	 * Assigns the specified subnet to the interface.
	 *
	 * @param subnet the subnet to assign
	 * @throws IOException if the subnet could not be assigned
	 */
	void addSubnet(Subnet subnet) throws IOException;

	/**
	 * Removes the specified subnet from the interface.
	 *
	 * @param subnet the subnet to remove
	 * @throws IOException if the subnet could not be removed
	 */
	void removeSubnet(Subnet subnet) throws IOException;

	/**
	 * Gets a list of all subnets assigned to the interface.
	 *
	 * @return a list of all subnets assigned to the interface
	 * @throws IOException if the subnets could not be retrieved
	 */
	Set<Subnet> subnets() throws IOException;

	/**
	 * Assigns the specified address to the interface.
	 *
	 * @param address the address to assign
	 * @throws IOException if the address could not be assigned
	 */
	default void addAddress(InetAddress address) throws IOException {
		addSubnet(Subnet.ofAddress(address));
	}

	/**
	 * Removes the specified address from the interface.
	 *
	 * @param address the address to remove
	 * @throws IOException if the address could not be removed
	 */
	default void removeAddress(InetAddress address) throws IOException {
		removeSubnet(Subnet.ofAddress(address));
	}

	void setMTU(int mtu) throws IOException;
	int mtu() throws IOException;

	/**
	 * A subnet is an IP address and a prefix length.
	 */
	record Subnet(InetAddress address, int prefixLength) {
		/**
		 * Returns true if this subnet is an IPv4 subnet.
		 * @return true if this subnet is an IPv4 subnet
		 */
		public boolean isIPv4() {
			return address.getAddress().length == 4;
		}

		/**
		 * Creates a subnet from a single address.  The prefix length of the returned subnet is 32 for IPv4 and 128 for IPv6.
		 */
		static Subnet ofAddress(InetAddress address) {
			return new Subnet(address, address.getAddress().length * 8);
		}

		public static Subnet ofMask(InetAddress address, InetAddress netmask) {
			return new Subnet(address, convertNetmaskToCIDR(netmask));
		}

		public static int convertNetmaskToCIDR(InetAddress netmask) {
			byte[] netmaskBytes = netmask.getAddress();
			int cidr = 0;
			boolean zero = false;
			for (byte b : netmaskBytes) {
				int mask = 0x80;

				for (int i = 0; i < 8; i++) {
					int result = b & mask;
					if (result == 0) {
						zero = true;
					} else if (zero) {
						throw new IllegalArgumentException("Invalid netmask.");
					} else {
						cidr++;
					}
					mask >>>= 1;
				}
			}
			return cidr;
		}


		public String toCIDRString() {
			return address.getHostAddress() + "/" + prefixLength;
		}
	}
}
