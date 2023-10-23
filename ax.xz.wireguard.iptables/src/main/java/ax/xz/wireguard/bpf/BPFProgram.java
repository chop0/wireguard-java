package ax.xz.wireguard.bpf;

import java.lang.foreign.MemoryLayout;
import java.lang.foreign.StructLayout;

import static java.lang.foreign.MemoryLayout.structLayout;
import static java.lang.foreign.MemoryLayout.unionLayout;
import static java.lang.foreign.ValueLayout.JAVA_INT;

public class BPFProgram {
	//	union bpf_attr {
//		struct {    /* Used by BPF_MAP_CREATE */
//			__u32         map_type;
//			__u32         key_size;    /* size of key in bytes */
//			__u32         value_size;  /* size of value in bytes */
//			__u32         max_entries; /* maximum number of entries
//                                                 in a map */
//		} map_create;
//
//		struct {    /* Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY
//                              commands */
//			__u32         map_fd;
//			__aligned_u64 key;
//			union {
//				__aligned_u64 value;
//				__aligned_u64 next_key;
//			};
//			__u64         flags;
//		} map_access;
//
//		struct {    /* Used by BPF_PROG_LOAD */
//			__u32         prog_type;
//			__u32         insn_cnt;
//			__aligned_u64 insns;      /* 'const struct bpf_insn *' */
//			__aligned_u64 license;    /* 'const char *' */
//			__u32         log_level;  /* verbosity level of verifier */
//			__u32         log_size;   /* size of user buffer */
//			__aligned_u64 log_buf;    /* user supplied 'char *'
//                                                buffer */
//			__u32         kern_version;
//                                             /* checked when prog_type=kprobe
//                                                (since Linux 4.1) */
//		} prog_load;
//	} __attribute__((aligned(8)));
//
	private static final MemoryLayout U32 = JAVA_INT.withByteAlignment(4);
	private static final MemoryLayout U64 = JAVA_INT.withByteAlignment(8);


	private static final MemoryLayout bpf_attr = unionLayout(
		structLayout( /* Used by BPF_MAP_CREATE */
			U32.withName("map_type"),
			U32.withName("key_size") /* size of key in bytes */,
			U32.withName("value_size") /* size of value in bytes */,
			U32.withName("max_entries") /* maximum number of entries in a map */
		).withName("map_create"),

		structLayout( /* Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY commands */
			U32.withName("map_fd"),
			U64.withName("key"),
			unionLayout(
				U64.withName("value"),
				U64.withName("next_key")
			).withName("value_or_next_key"),
			U64.withName("flags")
		).withName("map_access"),

		structLayout( /* Used by BPF_PROG_LOAD */
			U32.withName("prog_type"),
			U32.withName("insn_cnt"),
			U64.withName("insns") /* 'const struct bpf_insn *' */,
			U64.withName("license") /* 'const char *' */,
			U32.withName("log_level") /* verbosity level of verifier */,
			U32.withName("log_size") /* size of user buffer */,
			U64.withName("log_buf") /* user supplied 'char *' buffer */,
			U32.withName("kern_version") /* checked when prog_type=kprobe (since Linux 4.1) */
		).withName("prog_load")
	).withName("bpf_attr");


}
