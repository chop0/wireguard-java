package ax.xz.wireguard.device.message;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public sealed interface Message permits MessageCookieReply, MessageResponse, MessageTransport, MessageInitiation {
	static Message parse(ByteBuffer buffer) throws InvalidMessageException  {
		int type = buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN).getInt();
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
}
