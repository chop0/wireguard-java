package ax.xz.wireguard.util;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;

public class RollingAverage {
	private static final VarHandle INDEX;

	static {
		try {
			INDEX = MethodHandles.lookup().findVarHandle(RollingAverage.class, "index", long.class);
		} catch (NoSuchFieldException | IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private final String name;
	private final int size;

	private final long[] samples;

	private volatile long index = 0;

	public RollingAverage(String name, int size) {
		this.name = name;
		this.size = size;

		this.samples = new long[size];

		Thread.startVirtualThread(() -> {
			while (!Thread.interrupted()) {
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					throw new RuntimeException(e);
				}
				System.out.println("Average " + name + ": " + get());
			}
		});
	}

	public void add(long sample) {
		samples[(int) ((long) INDEX.getAndAdd(this, 1) % size)] = sample;
	}

	public long get() {
		long sum = 0;
		for (long sample : samples) {
			sum += sample;
		}
		return sum / size;
	}
}
