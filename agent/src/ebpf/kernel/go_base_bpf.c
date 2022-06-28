#define HASH_ENTRIES_MAX 40960

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct member_offsets);
	__uint(max_entries, HASH_ENTRIES_MAX);
} go_offsets_map SEC(".maps");


