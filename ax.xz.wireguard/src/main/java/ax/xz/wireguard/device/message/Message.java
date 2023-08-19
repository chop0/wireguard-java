package ax.xz.wireguard.device.message;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public sealed interface Message permits MessageCookieReply, MessageResponse, MessageTransport, MessageInitiation {
	static Message parse(ByteBuffer buffer) {
		int type = buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN).getInt();
		return switch (type) {
			case MessageInitiation.TYPE -> new MessageInitiation(buffer);
			case MessageResponse.TYPE -> new MessageResponse(buffer);
//			case 3 -> MessageCookieReply.parse(buffer);
			case 4 -> new MessageTransport(buffer);
			default -> throw new IllegalArgumentException("Unknown message type: " + type);
		};
	}
}
