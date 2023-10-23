package ax.xz.wireguard.bpf;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.SegmentAllocator;

public class BPFMap {
	private final int fd;
	private final int keySize, valueSize, maxEntries;

	private BPFMap(int fd, int keySize, int valueSize, int maxEntries) {
		this.fd = fd;
		this.keySize = keySize;
		this.valueSize = valueSize;
		this.maxEntries = maxEntries;
	}

	public static BPFMap create(int keySize, int valueSize, int maxEntries) {
		throw new UnsupportedOperationException();
	}

	public MemorySegment lookup(SegmentAllocator allocator, MemorySegment key) {
		if (key.byteSize() != keySize) {
			throw new IllegalArgumentException("key size mismatch");
		}

		var value = allocator.allocate(valueSize);
		int result = lookup0(key, value);
		if (result < 0) {
			if (result == ENOENT) {
				return null;
			} else {
				throw new RuntimeException("lookup failed: " + result);
			}
		}

		return value;
	}

	enum Type {
		BPF_MAP_TYPE_UNSPEC,  /* Reserve 0 as invalid map type */
		BPF_MAP_TYPE_HASH,
		BPF_MAP_TYPE_ARRAY,
		BPF_MAP_TYPE_PROG_ARRAY,
		BPF_MAP_TYPE_PERF_EVENT_ARRAY,
		BPF_MAP_TYPE_PERCPU_HASH,
		BPF_MAP_TYPE_PERCPU_ARRAY,
		BPF_MAP_TYPE_STACK_TRACE,
		BPF_MAP_TYPE_CGROUP_ARRAY,
		BPF_MAP_TYPE_LRU_HASH,
		BPF_MAP_TYPE_LRU_PERCPU_HASH,
		BPF_MAP_TYPE_LPM_TRIE,
		BPF_MAP_TYPE_ARRAY_OF_MAPS,
		BPF_MAP_TYPE_HASH_OF_MAPS,
		BPF_MAP_TYPE_DEVMAP,
		BPF_MAP_TYPE_SOCKMAP,
		BPF_MAP_TYPE_CPUMAP,
		BPF_MAP_TYPE_XSKMAP,
		BPF_MAP_TYPE_SOCKHASH,
		BPF_MAP_TYPE_CGROUP_STORAGE,
		BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
		BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
		BPF_MAP_TYPE_QUEUE,
		BPF_MAP_TYPE_STACK,
		/* See /usr/include/linux/bpf.h for the full list. */
	}

	;
}
