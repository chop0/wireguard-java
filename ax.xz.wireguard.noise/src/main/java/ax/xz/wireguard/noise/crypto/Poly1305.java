package ax.xz.wireguard.noise.crypto;

import java.lang.foreign.MemorySegment;

public interface Poly1305 {
	void init(MemorySegment key);

	void update(MemorySegment message);

	void finish(MemorySegment mac);

	byte[] finish();
}
