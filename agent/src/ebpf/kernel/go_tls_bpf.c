// FIXME: should come from user space

#define OFFSET_TLS_CONN_CONN 0 // crypto/tls.Conn conn
#define OFFSET_NET_POLL_FD_SYSFD 16 // net.poll.FD Sysfd

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tls_conn_key);
	__type(value, struct tls_conn);
	__uint(max_entries, MAX_SYSTEM_THREADS);
} tls_conn_map SEC(".maps");

static int get_fd_from_tls_conn(void *tls_conn)
{
	struct go_interface i = {};
	void *ptr;
	int fd;

	bpf_probe_read_user(&i, sizeof(i), tls_conn + OFFSET_TLS_CONN_CONN);
	bpf_probe_read_user(&ptr, sizeof(ptr), i.ptr);
	bpf_probe_read_user(&fd, sizeof(fd), ptr + OFFSET_NET_POLL_FD_SYSFD);

	return fd;
}

SEC("uprobe/go_tls_write_enter")
int uprobe_go_tls_write_enter(struct pt_regs *ctx)
{
	struct tls_conn c = {};
	struct tls_conn_key key = {};

	// TODO: Get parameters on the stack
	c.buffer = (char *)ctx->rbx;
	c.fd = get_fd_from_tls_conn((void *)ctx->rax);
	c.tcp_seq = get_tcp_write_seq_from_fd(c.fd);

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	bpf_map_update_elem(&tls_conn_map, &key, &c, BPF_ANY);

	return 0;
}

SEC("uprobe/go_tls_write_exit")
int uprobe_go_tls_write_exit(struct pt_regs *ctx)
{
	struct tls_conn *c;
	struct tls_conn_key key = {};
	ssize_t bytes_count;

	// TODO: Get parameters on the stack
	if (!ctx->rax)
		return 0;
	bytes_count = ctx->rax;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c)
		return 0;

	struct data_args_t write_args = {};
	write_args.buf = c->buffer;
	write_args.fd = c->fd;
	write_args.enter_ts = bpf_ktime_get_ns();

	__u64 id = bpf_get_current_pid_tgid();
	struct process_data_extra extra = {
		.tls = true,
		.go = true,
		.use_tcp_seq = true,
		.tcp_seq = c->tcp_seq,
		.coroutine_id = key.goid,
	};
	process_uprobe_data_tls((struct pt_regs *)ctx, id, T_EGRESS,
				&write_args, bytes_count, &extra);
	return 0;
}

SEC("uprobe/go_tls_read_enter")
int uprobe_go_tls_read_enter(struct pt_regs *ctx)
{
	struct tls_conn c = {};
	struct tls_conn_key key = {};

	// TODO: Get parameters on the stack
	c.buffer = (char *)ctx->rbx;
	c.fd = get_fd_from_tls_conn((void *)ctx->rax);
	c.tcp_seq = get_tcp_read_seq_from_fd(c.fd);

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	bpf_map_update_elem(&tls_conn_map, &key, &c, BPF_ANY);

	return 0;
}

SEC("uprobe/go_tls_read_exit")
int uprobe_go_tls_read_exit(struct pt_regs *ctx)
{
	struct tls_conn *c;
	struct tls_conn_key key = {};
	ssize_t bytes_count;

	// TODO: Get parameters on the stack
	if (!ctx->rax)
		return 0;
	bytes_count = ctx->rax;

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c)
		return 0;

	struct data_args_t read_args = {};
	read_args.buf = c->buffer;
	read_args.fd = c->fd;
	read_args.enter_ts = bpf_ktime_get_ns();

	__u64 id = bpf_get_current_pid_tgid();
	struct process_data_extra extra = {
		.tls = true,
		.go = true,
		.use_tcp_seq = true,
		.tcp_seq = c->tcp_seq,
		.coroutine_id = key.goid,
	};

	process_uprobe_data_tls((struct pt_regs *)ctx, id, T_INGRESS,
				&read_args, bytes_count, &extra);
	return 0;
}
