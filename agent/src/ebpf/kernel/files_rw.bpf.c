/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2025- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

// Default value set when file read/write latency timestamp rollback occurs.
#define TIME_ROLLBACK_DEFAULT_LATENCY_NS 50000
#define FILE_TYPE_ERROR    (-1)  /* Error or invalid file */
#define FILE_TYPE_REGULAR   0    /* Regular VFS-backed file */
#define FILE_TYPE_VIRTUAL   1    /* Non-VFS / virtual / special file */

static __inline int check_file_type(void *file, struct member_fields_offset *offset)
{
	if (!file || !offset)
		return FILE_TYPE_ERROR;

	/*
	 * Determine whether a file belongs to a regular VFS filesystem
	 * based on the existence of file->f_op->read_iter.
	 *
	 * file->f_op->read_iter != NULL:
	 *   Regular VFS-backed files, including:
	 *     - ext4 / xfs / btrfs
	 *     - NFS / CIFS / CephFS
	 *     - tmpfs / ramfs
	 *     - overlayfs
	 *     - fuse
	 *
	 * file->f_op->read_iter == NULL:
	 *   Non-VFS or special kernel objects, including:
	 *     - IPC objects (pipe / fifo)
	 *     - socket-related objects
	 *     - anon_inode derived objects
	 *     - some procfs / sysfs entries
	 *     - certain character devices or special driver files
	 *     - kernel objects without regular VFS file semantics
	 */
	void *f_op, *read_iter;
	bpf_probe_read_kernel(&f_op, sizeof(f_op),
			      file + offset->struct_file_f_op_offset);
	if (f_op == NULL)
		return FILE_TYPE_ERROR;

	bpf_probe_read_kernel(&read_iter, sizeof(read_iter),
			      f_op +
			      offset->struct_file_operations_read_iter_offset);
	if (read_iter == NULL)
		return FILE_TYPE_VIRTUAL;

	return FILE_TYPE_REGULAR;
}

static __inline bool is_readable_file(int fd,
				      bool disable_vfile_collect,
				      struct member_fields_offset *off_ptr)
{
	struct member_fields_offset *offset = off_ptr;
	if (offset == NULL) {
		__u32 k0 = 0;
		offset = members_offset__lookup(&k0);
	}
	void *file = fd_to_file(fd, offset);
	if (file == NULL)
		return false;

	if (disable_vfile_collect &&
	    check_file_type(file, offset) != FILE_TYPE_REGULAR)
			return false;

	/*
	 * Further ensure that it is a regular inode file, exclude
	 * socket / pipe / anon_inode / directories / symbolic links.
	 */
	__u32 i_mode = file_to_i_mode(file, offset);
	return S_ISREG(i_mode);
}

static __inline void *get_mount_ptr(void *file,
				    struct member_fields_offset *off_ptr)
{
	void *vfsmount = NULL;

	/*
	 * struct_file_f_path_offset: Starting from Linux 6.5, this offset has
	 * undergone significant changes and automatic inference is not supported.
	 */

	// file -> path -> vfsmount
	bpf_probe_read_kernel(&vfsmount, sizeof(vfsmount),
			      file + off_ptr->struct_file_f_path_offset +
			      off_ptr->struct_path_mnt_offset);
	if (vfsmount == NULL)
		return NULL;

	// `vfsmount` is embedded in `struct mount`
	return (vfsmount - off_ptr->struct_mount_mnt_offset);
}

static __inline void get_mount_ids(void *file,
				   struct __io_event_buffer *buffer,
				   struct member_fields_offset *off_ptr)
{
	void *mount, *mnt_ns = NULL;
	buffer->mntns_id = 0;
	buffer->mnt_id = -1;
	mount = get_mount_ptr(file, off_ptr);
	if (mount == NULL)
		return;

	//bpf_debug("mount_mnt_id_offset 0x%x\n", off_ptr->struct_mount_mnt_id_offset);
	if (off_ptr->struct_mount_mnt_id_offset != INVALID_OFFSET) {
		bpf_probe_read_kernel(&buffer->mnt_id, sizeof(buffer->mnt_id),
				      mount +
				      off_ptr->struct_mount_mnt_id_offset);
	}

	if (off_ptr->struct_mount_mnt_ns_offset == INVALID_OFFSET)
		return;

	bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns),
			      mount + off_ptr->struct_mount_mnt_ns_offset);
	if (mnt_ns == NULL)
		return;

	// mnt_namespace -> ns_common -> inum
	bpf_probe_read_kernel(&buffer->mntns_id, sizeof(buffer->mntns_id),
			      mnt_ns + off_ptr->struct_mnt_namespace_ns_offset +
			      off_ptr->struct_ns_common_inum_offset);
}

static __inline int infer_mount_offset(int fd,
				       struct member_fields_offset *off_ptr)
{
	// The inference has been completed.
	if (off_ptr->files_infer_done)
		return 0;

	__u32 k0 = 0;
	struct adapt_kern_data *adapt_data;
	adapt_data = adapt_kern_data_map__lookup(&k0);
	if (!adapt_data)
		goto error;

	// The inference is limited to the threads we have designated.
	if (adapt_data->id != bpf_get_current_pid_tgid())
		return -1;

	void *file = fd_to_file(fd, off_ptr);
	if (file == NULL)
		goto error;

	void *mount = get_mount_ptr(file, off_ptr);
	if (mount == NULL)
		goto error;

	int i, mnt_id = 0;
	bool found = false;
	__u16 mnt_id_offsets[] = { 0x10c, 0x114, 0x11c, 0x124 };
#pragma unroll
	for (i = 0; i < ARRAY_SIZE(mnt_id_offsets); i++) {
		bpf_probe_read_kernel(&mnt_id, sizeof(mnt_id),
				      mount + mnt_id_offsets[i]);
		if (mnt_id == adapt_data->mnt_id) {
			found = true;
			break;
		}
	}

	if (found) {
		off_ptr->struct_mount_mnt_id_offset = mnt_id_offsets[i];
	} else {
		off_ptr->struct_mount_mnt_id_offset = INVALID_OFFSET;
	}

	__u32 mntns_id = 0;
	void *mnt_ns = NULL;
	__u16 mnt_ns_offset[] = { 0xe0, 0xe8 };
	off_ptr->struct_mount_mnt_ns_offset = INVALID_OFFSET;
	off_ptr->struct_mnt_namespace_ns_offset = INVALID_OFFSET;
#pragma unroll
	for (i = 0; i < ARRAY_SIZE(mnt_ns_offset); i++) {
		bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns),
				      mount + mnt_ns_offset[i]);
		if (mnt_ns == NULL)
			continue;
		// mnt_namespace -> ns_common -> inum
		bpf_probe_read_kernel(&mntns_id, sizeof(mntns_id),
				      mnt_ns +
				      off_ptr->struct_ns_common_inum_offset);
		if (mntns_id == adapt_data->mntns_id) {
			found = true;
			off_ptr->struct_mount_mnt_ns_offset = mnt_ns_offset[i];
			off_ptr->struct_mnt_namespace_ns_offset = 0;
			off_ptr->files_infer_done = 1;
			return 0;
		}
		bpf_probe_read_kernel(&mntns_id, sizeof(mntns_id),
				      mnt_ns + 0x8 +
				      off_ptr->struct_ns_common_inum_offset);
		if (mntns_id == adapt_data->mntns_id) {
			off_ptr->struct_mount_mnt_ns_offset = mnt_ns_offset[i];
			off_ptr->struct_mnt_namespace_ns_offset = 0x8;
			off_ptr->files_infer_done = 1;
			return 0;
		}
	}

	off_ptr->files_infer_done = 1;
	return -1;

error:
	off_ptr->struct_mount_mnt_id_offset = INVALID_OFFSET;
	off_ptr->struct_mount_mnt_ns_offset = INVALID_OFFSET;
	off_ptr->struct_mnt_namespace_ns_offset = INVALID_OFFSET;
	off_ptr->files_infer_done = 1;
	return -1;
}

static __inline void set_file_metric_data(struct __io_event_buffer *buffer,
					  struct __socket_data *v,
					  int fd,
					  struct member_fields_offset *off_ptr)
{
#define MAX_DIRECTORY_DEPTH 18

	struct member_fields_offset *offset = off_ptr;
	if (offset == NULL) {
		__u32 k0 = 0;
		offset = members_offset__lookup(&k0);
	}

	void *file = fd_to_file(fd, offset);
	if (file == NULL)
		return;

	/*
	 * Get the underlying device number of the superblock, which indicates
	 * the device where the file system is mounted, and use it in user space
	 * to determine the mount point of the file.
	 *
	 * struct file {
	 *    ...
	 *    struct inode *f_inode;
	 * };
	 * struct inode {
	 *    ...
	 *    struct super_block *i_sb;
	 * };
	 * struct super_block {
	 *    ...
	 *    kern_dev_t s_dev;
	 * };
	 */
	void *ptr = NULL;
	// Fetch struct inode *f_inode
	bpf_probe_read_kernel(&ptr, sizeof(ptr),
			      file + offset->struct_file_f_inode_offset);
	if (!ptr)
		return;

	// Fetch struct super_block *i_sb;
	bpf_probe_read_kernel(&ptr, sizeof(ptr),
			      ptr + offset->struct_inode_i_sb_offset);
	if (!ptr)
		return;

	bpf_probe_read_kernel(&v->s_dev, sizeof(v->s_dev),
			      ptr + offset->struct_super_block_s_dev_offset);
	bpf_probe_read_kernel(&buffer->offset, sizeof(buffer->offset),
			      file + offset->struct_file_f_pos_offset);
	void *dentry = NULL, *parent;
	bpf_probe_read_kernel(&dentry, sizeof(dentry),
			      file + offset->struct_file_dentry_offset);
	get_mount_ids(file, buffer, offset);
	//bpf_debug("buffer->mnt_id %d\n", buffer->mnt_id);
	buffer->len = 0;
#pragma unroll
	for (int i = 0; i < MAX_DIRECTORY_DEPTH; i++) {
		char *name = NULL;
		bpf_probe_read_kernel(&name, sizeof(name),
				      dentry +
				      offset->struct_dentry_name_offset);
		struct __dentry_name *d_n =
		    (struct __dentry_name *)(buffer->filename + buffer->len);
		if (buffer->len + sizeof(d_n->name) > sizeof(buffer->filename))
			break;
		buffer->len +=
		    bpf_probe_read_kernel_str(d_n->name, sizeof(d_n->name),
					      name);

		bpf_probe_read_kernel(&parent, sizeof(parent),
				      dentry +
				      offset->struct_dentry_d_parent_offset);

		if (parent == dentry || parent == NULL)
			break;
		dentry = parent;
	}
}

static __inline int trace_io_event_common(void *ctx,
					  struct member_fields_offset *offset,
					  struct data_args_t *data_args,
					  enum traffic_direction direction,
					  __u64 pid_tgid)
{
	__u64 latency = 0, curr_ts;
	__u64 trace_id = 0;
	__u32 k0 = 0;
	__u32 tgid = pid_tgid >> 32;

	if (data_args->bytes_count <= 0) {
		return -1;
	}

	struct tracer_ctx_s *tracer_ctx = tracer_ctx_map__lookup(&k0);
	if (tracer_ctx == NULL) {
		return -1;
	}

	if (tracer_ctx->io_event_collect_mode == 0) {
		return -1;
	}

	__u32 timeout = tracer_ctx->go_tracing_timeout;
	struct trace_key_t trace_key = get_trace_key(timeout, false);
	struct trace_info_t *trace_info_ptr = trace_map__lookup(&trace_key);
	if (trace_info_ptr) {
		trace_id = trace_info_ptr->thread_trace_id;
	}

	if (trace_id == 0 && tracer_ctx->io_event_collect_mode == 1) {
		return -1;
	}

	int data_max_sz = tracer_ctx->data_limit_max;

	if (!is_readable_file(data_args->fd,
			      !tracer_ctx->virtual_file_collect_enabled,
			      offset)) {
		return -1;
	}

	curr_ts = bpf_ktime_get_ns();
	latency = curr_ts - data_args->enter_ts;

	/*
	 * When using `bpf_ktime_get_ns()` to calculate latency, set `latency`
	 * to TIME_ROLLBACK_DEFAULT_LATENCY_NS (50 microseconds) if a time rollback
	 * (non-monotonic behavior) is detected. This is commonly observed on
	 * CentOS with the 3.10 kernel.
	 */
	if (unlikely(curr_ts < data_args->enter_ts)) {
		latency = TIME_ROLLBACK_DEFAULT_LATENCY_NS;
	}

	if (latency < tracer_ctx->io_event_minimal_duration) {
		return -1;
	}

	struct __io_event_buffer *buffer = io_event_buffer__lookup(&k0);
	if (!buffer) {
		return -1;
	}

	buffer->bytes_count = data_args->bytes_count;
	buffer->latency = latency;
	buffer->operation = direction;
	struct __socket_data_buffer *v_buff =
	    bpf_map_lookup_elem(&NAME(data_buf), &k0);
	if (!v_buff)
		return -1;

	__sync_fetch_and_add(&tracer_ctx->push_buffer_refcnt, 1);
	struct __socket_data *v = (struct __socket_data *)&v_buff->data[0];

	if (v_buff->len > (sizeof(v_buff->data) - sizeof(*v))) {
		__sync_fetch_and_add(&tracer_ctx->push_buffer_refcnt, -1);
		return -1;
	}

	v = (struct __socket_data *)(v_buff->data + v_buff->len);
	__builtin_memset(v, 0, offsetof(typeof(struct __socket_data), data));
	set_file_metric_data(buffer, v, data_args->fd, offset);
	v->fd = data_args->fd;
	v->tgid = tgid;
	v->pid = (__u32) pid_tgid;
	v->coroutine_id = trace_key.goid;
	v->timestamp = data_args->enter_ts;
	v->syscall_len = sizeof(*buffer);
	v->source = DATA_SOURCE_IO_EVENT;
	v->thread_trace_id = trace_id;
	v->msg_type = MSG_COMMON;
	bpf_get_current_comm(v->comm, sizeof(v->comm));
#if !defined(LINUX_VER_KFUNC) && !defined(LINUX_VER_5_2_PLUS)
	struct tail_calls_context *context =
	    (struct tail_calls_context *)v->data;
	context->max_size_limit = data_max_sz;
	context->push_reassembly_bytes = 0;
	context->vecs = false;
	context->is_close = false;
	context->dir = direction;
#ifdef SUPPORTS_KPROBE_ONLY
	bpf_tail_call(ctx, &NAME(progs_jmp_kp_map), PROG_OUTPUT_DATA_KP_IDX);
#else
	bpf_tail_call(ctx, &NAME(progs_jmp_tp_map), PROG_OUTPUT_DATA_TP_IDX);
#endif
	return 0;
#else
	return __output_data_common(ctx, tracer_ctx, v_buff, data_args,
				    direction, false, data_max_sz, false, 0);
#endif
}

/*
 * File read/write-related system call collection points.
 */

// File Read Event Tracing
static __inline int do_sys_enter_pread(int fd, enum syscall_src_func fn)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return 0;

	// Attempt to infer file-related structure offsets.
	infer_mount_offset(fd, offset);

	__u64 id = bpf_get_current_pid_tgid();
	// Stash arguments.
	struct data_args_t read_args = {};
	read_args.source_fn = fn;
	read_args.fd = fd;
	read_args.enter_ts = bpf_ktime_get_ns();
	active_read_args_map__update(&id, &read_args);
	return 0;
}

#ifdef SUPPORTS_KPROBE_ONLY
//ssize_t ksys_pread64(unsigned int fd, char __user *buf, size_t count,
//                     loff_t pos)
KPROG(ksys_pread64) (struct pt_regs * ctx) {
	int fd = (unsigned int)PT_REGS_PARM1(ctx);
	return do_sys_enter_pread(fd, SYSCALL_FUNC_PREAD64);
}

/*
 * preadv()/preadv2() -> do_preadv()
 * static ssize_t do_preadv(unsigned long fd, const struct iovec __user *vec,
 *			    unsigned long vlen, loff_t pos, rwf_t flags);
 */
KPROG(do_preadv) (struct pt_regs * ctx) {
	int fd = (unsigned int)PT_REGS_PARM1(ctx);
	return do_sys_enter_pread(fd, SYSCALL_FUNC_PREADV);
}
#else
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_pread64/format
TP_SYSCALL_PROG(enter_pread64) (struct syscall_comm_enter_ctx * ctx) {
	int fd = ctx->fd;
	return do_sys_enter_pread(fd, SYSCALL_FUNC_PREAD64);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_preadv/format
TP_SYSCALL_PROG(enter_preadv) (struct syscall_comm_enter_ctx * ctx) {
	int fd = ctx->fd;
	return do_sys_enter_pread(fd, SYSCALL_FUNC_PREADV);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_preadv2/format
TP_SYSCALL_PROG(enter_preadv2) (struct syscall_comm_enter_ctx * ctx) {
	int fd = ctx->fd;
	return do_sys_enter_pread(fd, SYSCALL_FUNC_PREADV2);
}
#endif /* SUPPORTS_KPROBE_ONLY */

static __inline int do_sys_exit_pread(void *ctx, ssize_t bytes_count)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	// Unstash arguments, and process syscall.
	struct data_args_t *read_args = active_read_args_map__lookup(&id);
	if (read_args != NULL) {
		read_args->bytes_count = bytes_count;
		trace_io_event_common(ctx, offset, read_args, T_INGRESS, id);
	}

	active_read_args_map__delete(&id);
	return 0;
}

#ifdef SUPPORTS_KPROBE_ONLY
KRETPROG(ksys_pread64) (struct pt_regs * ctx) {
	ssize_t bytes_count = PT_REGS_RC(ctx);
	return do_sys_exit_pread((void *)ctx, bytes_count);
}

KRETPROG(do_preadv) (struct pt_regs * ctx) {
	ssize_t bytes_count = PT_REGS_RC(ctx);
	return do_sys_exit_pread((void *)ctx, bytes_count);
}
#else
// /sys/kernel/debug/tracing/events/syscalls/sys_exit_pwrite64/format
TP_SYSCALL_PROG(exit_pread64) (struct syscall_comm_exit_ctx * ctx) {
	return do_sys_exit_pread((void *)ctx, (ssize_t) ctx->ret);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_pwritev/format
TP_SYSCALL_PROG(exit_preadv) (struct syscall_comm_exit_ctx * ctx) {
	return do_sys_exit_pread((void *)ctx, (ssize_t) ctx->ret);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_pwritev2/format
TP_SYSCALL_PROG(exit_preadv2) (struct syscall_comm_exit_ctx * ctx) {
	return do_sys_exit_pread((void *)ctx, (ssize_t) ctx->ret);
}
#endif /* SUPPORTS_KPROBE_ONLY */

// File Write Event Tracing
static __inline int do_sys_enter_pwrite(int fd, enum syscall_src_func fn)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	struct data_args_t write_args = {};
	write_args.source_fn = fn;
	write_args.fd = fd;
	write_args.enter_ts = bpf_ktime_get_ns();
	active_write_args_map__update(&id, &write_args);
	return 0;
}

//ssize_t ksys_pwrite64(unsigned int fd, const char __user *buf,
//                      size_t count, loff_t pos);
#ifdef SUPPORTS_KPROBE_ONLY
KPROG(ksys_pwrite64) (struct pt_regs * ctx) {
	int fd = (int)PT_REGS_PARM1(ctx);
	return do_sys_enter_pwrite(fd, SYSCALL_FUNC_PWRITE64);
}

/*
 * pwritev()/pwritev2() -> do_pwritev()
 * static ssize_t do_pwritev(unsigned long fd, const struct iovec __user *vec,
 *                           unsigned long vlen, loff_t pos, rwf_t flags);
 */
KPROG(do_pwritev) (struct pt_regs * ctx) {
	int fd = (int)PT_REGS_PARM1(ctx);
	return do_sys_enter_pwrite(fd, SYSCALL_FUNC_PWRITEV);
}
#else
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_pwrite64/format
TP_SYSCALL_PROG(enter_pwrite64) (struct syscall_comm_enter_ctx * ctx) {
	int fd = ctx->fd;
	return do_sys_enter_pwrite(fd, SYSCALL_FUNC_PWRITE64);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_pwritev/format
TP_SYSCALL_PROG(enter_pwritev) (struct syscall_comm_enter_ctx * ctx) {
	int fd = ctx->fd;
	return do_sys_enter_pwrite(fd, SYSCALL_FUNC_PWRITEV);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_pwritev2/format
TP_SYSCALL_PROG(enter_pwritev2) (struct syscall_comm_enter_ctx * ctx) {
	int fd = ctx->fd;
	return do_sys_enter_pwrite(fd, SYSCALL_FUNC_PWRITEV2);
}
#endif /* SUPPORTS_KPROBE_ONLY */

// pwrite64()/pwritev()/pwritev2() exit
static __inline int do_sys_exit_pwrite(void *ctx, ssize_t bytes_count)
{
	__u32 k0 = 0;
	struct member_fields_offset *offset = members_offset__lookup(&k0);
	if (!offset)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	// Unstash arguments, and process syscall.
	struct data_args_t *write_args = active_write_args_map__lookup(&id);
	if (write_args != NULL) {
		write_args->bytes_count = bytes_count;
		trace_io_event_common(ctx, offset, write_args, T_EGRESS, id);
	}

	active_write_args_map__delete(&id);
	return 0;
}

#ifdef SUPPORTS_KPROBE_ONLY
KRETPROG(ksys_pwrite64) (struct pt_regs * ctx) {
	ssize_t bytes_count = PT_REGS_RC(ctx);
	return do_sys_exit_pwrite((void *)ctx, bytes_count);
}

KRETPROG(do_pwritev) (struct pt_regs * ctx) {
	ssize_t bytes_count = PT_REGS_RC(ctx);
	return do_sys_exit_pwrite((void *)ctx, bytes_count);
}
#else
// /sys/kernel/debug/tracing/events/syscalls/sys_exit_pwrite64/format
TP_SYSCALL_PROG(exit_pwrite64) (struct syscall_comm_exit_ctx * ctx) {
	return do_sys_exit_pwrite((void *)ctx, (ssize_t) ctx->ret);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_pwritev/format
TP_SYSCALL_PROG(exit_pwritev) (struct syscall_comm_exit_ctx * ctx) {
	return do_sys_exit_pwrite((void *)ctx, (ssize_t) ctx->ret);
}

// /sys/kernel/debug/tracing/events/syscalls/sys_exit_pwritev2/format
TP_SYSCALL_PROG(exit_pwritev2) (struct syscall_comm_exit_ctx * ctx) {
	return do_sys_exit_pwrite((void *)ctx, (ssize_t) ctx->ret);
}
#endif /* SUPPORTS_KPROBE_ONLY */

#ifndef SUPPORTS_KPROBE_ONLY
PROGTP(io_event) (void *ctx) {
#else
PROGKP(io_event) (void *ctx) {
#endif
	__u64 id = bpf_get_current_pid_tgid();

	struct data_args_t *data_args = NULL;

	data_args = active_read_args_map__lookup(&id);
	if (data_args) {
		trace_io_event_common(ctx, NULL, data_args, T_INGRESS, id);
		active_read_args_map__delete(&id);
		return 0;
	}

	data_args = active_write_args_map__lookup(&id);
	if (data_args) {
		trace_io_event_common(ctx, NULL, data_args, T_EGRESS, id);
		active_write_args_map__delete(&id);
		return 0;
	}

	return 0;
}
