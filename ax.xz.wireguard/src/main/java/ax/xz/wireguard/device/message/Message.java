package ax.xz.wireguard.device.message;

import ax.xz.wireguard.device.BufferPool;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public sealed interface Message extends AutoCloseable permits MessageResponse, MessageTransport, MessageInitiation {
	static Message parse(BufferPool.BufferGuard buffer) throws InvalidMessageException  {
		int type = buffer.buffer().duplicate().order(ByteOrder.LITTLE_ENDIAN).getInt();
		return switch (type) {
			case MessageInitiation.TYPE -> new MessageInitiation(buffer);
			case MessageResponse.TYPE -> new MessageResponse(buffer);
//			case 3 -> MessageCookieReply.parse(buffer);
			case MessageTransport.TYPE -> new MessageTransport(buffer);
			default -> throw new InvalidMessageException(type);
		};
	}

	class InvalidMessageException extends IOException {
		public InvalidMessageException(int givenType) {
			super("Unknown message type: " + givenType);
		}
	}

	@Override
	void close();
}
