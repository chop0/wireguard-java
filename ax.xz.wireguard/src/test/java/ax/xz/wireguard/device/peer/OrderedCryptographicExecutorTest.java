package ax.xz.wireguard.device.peer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OrderedCryptographicExecutorTest {

	@Test
	void test() throws InterruptedException {
		var queue = new OrderedCryptographicExecutor<Integer, String>(16, Object::toString, (t, i) -> {});
		for (int i = 0; i < 10_000; i++)
			queue.enqueue(i);

		for (int i = 0; i < 10_000; i++)
			assertEquals(Integer.toString(i), queue.dequeue());
	}
}