#define HASH_ENTRIES_MAX 40960

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct member_offsets);
	__uint(max_entries, HASH_ENTRIES_MAX);
} go_offsets_map SEC(".maps");


// FIXME: should come from user space
#define OFFSET_G_GOID 152 // runtime.g goid

struct {
	// FIXME: LRU should be replaced when there is a better way to free memory
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __s64);
	__uint(max_entries, MAX_SYSTEM_THREADS);
} goroutines_map SEC(".maps");

static __s64 get_current_goroutine(void)
{
	__u64 current_thread = bpf_get_current_pid_tgid();
	__s64 *goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
	if (goid_ptr)
		return *goid_ptr;
	else
		return 0;
}

SEC("uprobe/runtime.casgstatus")
int runtime_casgstatus(struct pt_regs *ctx)
{
	__s32 newval = (__s32)(ctx->rcx);

	if (newval != 2)
		return 0;

	void *g_ptr = (void *)(ctx->rax);

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + OFFSET_G_GOID);
	__u64 current_thread = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&goroutines_map, &current_thread, &goid, BPF_ANY);

	return 0;
}
