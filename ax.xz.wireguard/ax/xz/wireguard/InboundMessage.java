package ax.xz.wireguard;

import java.net.SocketAddress;

/**
 * A message and its origin
 * @param address the address from which the message originated
 * @param message the message
 * @param <T>
 */
public record InboundMessage<T extends Message>(SocketAddress address, T message) {
}
