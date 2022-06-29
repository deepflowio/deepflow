#define HASH_ENTRIES_MAX 40960

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct member_offsets);
	__uint(max_entries, HASH_ENTRIES_MAX);
} go_offsets_map SEC(".maps");

static __inline int get_uprobe_offset(int offset_idx){
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct member_offsets *offsets;
	offsets = bpf_map_lookup_elem(&go_offsets_map, &pid);
	if (offsets) {
		return offsets->data[offset_idx];
	} else {
		return -1;
	}
}

static __inline __u32 get_go_version(void)
{
	__u64 id;
	pid_t pid;

	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	struct member_offsets *offsets;
	offsets = bpf_map_lookup_elem(&go_offsets_map, &pid);
	if (offsets) {
		return offsets->version;
	} else {
		return 0;
	}
}

static __inline int get_runtime_g_goid_offset(void)
{
	return get_uprobe_offset(runtime_g_goid_offset);
}

static __inline int get_crypto_tls_conn_conn_offset(void)
{
	return get_uprobe_offset(crypto_tls_conn_conn_offset);
}

static __inline int get_net_poll_fd_sysfd(void)
{
	return get_uprobe_offset(net_poll_fd_sysfd);
}

struct {
	// FIXME: LRU should be replaced when there is a better way to free memory
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, __s64);
	__uint(max_entries, MAX_SYSTEM_THREADS);
} goroutines_map SEC(".maps");

static __inline __s64 get_current_goroutine(void)
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
	int offset_g_goid = get_runtime_g_goid_offset();
	if (offset_g_goid < 0)
		return 0;

	__s32 newval;
	void *g_ptr;

	if (get_go_version() >= GO_VERSION(1, 17, 0)) {
		g_ptr = (void *)(ctx->rax);
		newval = (__s32)(ctx->rcx);
	} else {
		bpf_probe_read(&g_ptr, sizeof(g_ptr), (void *)(ctx->rsp + 8));
		bpf_probe_read(&newval, sizeof(newval),
			       (void *)(ctx->rsp + 20));
	}

	if (newval != 2)
		return 0;

	__s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + offset_g_goid);
	
	__u64 current_thread = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&goroutines_map, &current_thread, &goid, BPF_ANY);

	return 0;
}
