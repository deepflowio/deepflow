/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2022- The Yunshan Networks Authors.
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

#ifndef DF_TASK_STRUCT_UTILS_H
#define DF_TASK_STRUCT_UTILS_H

#include <linux/sched.h>
#include <math.h>
#include "utils.h"

#define NSEC_PER_SEC	1000000000L
#define USER_HZ		100

static __inline void *get_socket_file_addr_with_check(struct task_struct *task,
						      int fd_num,
						      int files_off,
						      int fdt_off)
{
	void *file = NULL;
	void *files, *files_ptr = (void *)task + files_off;
	bpf_probe_read_kernel(&files, sizeof(files), files_ptr);

	if (files == NULL)
		return NULL;

	struct fdtable *fdt, __fdt;

	bpf_probe_read_kernel(&fdt, sizeof(fdt), files + fdt_off);
	bpf_probe_read_kernel(&__fdt, sizeof(__fdt), (void *)fdt);

	if (fd_num >= (int)__fdt.max_fds)
		return NULL;

	bpf_probe_read_kernel(&file, sizeof(file), __fdt.fd + fd_num);

	return file;
}

static __inline void *retry_get_socket_file_addr(struct task_struct *task,
						 int fd_num, int fdt_offset,
						 int files_off)
{
	void *file = NULL;
	void *files, *files_ptr = (void *)task + files_off;
	bpf_probe_read_kernel(&files, sizeof(files), files_ptr);

	if (files == NULL)
		return NULL;

	struct fdtable *fdt, __fdt;
	bpf_probe_read_kernel(&fdt, sizeof(fdt), files + fdt_offset);
	bpf_probe_read_kernel(&__fdt, sizeof(__fdt), (void *)fdt);
	bpf_probe_read_kernel(&file, sizeof(file), __fdt.fd + fd_num);

	return file;
}

static __inline void *infer_and_get_socket_from_fd(int fd_num, struct member_fields_offset
						   *offset, bool debug)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	void *file = NULL;
	void *private_data = NULL;
	struct socket *socket;
	struct socket __socket;
	int i;

/* *INDENT-OFF* */
	// TAG: STRUCT_TASK_FILES_OFFSET
	// 成员 files 在 struct task_struct 中的偏移量
#ifdef LINUX_VER_5_2_PLUS
	// 0xa48 for 5.10.0-60.18.0.50.h322_1.hce2.aarch64
	// 0xc60 for 5.10.0-106.18.0.68.oe2209.x86_64
	int files_offset_array[] = {
		0x790, 0xa80, 0xa88, 0xa90, 0xa98, 0xaa0, 0xaa8, 0xab0, 0xab8, 0xac0,
		0xac8, 0xad0, 0xad8, 0xae0, 0xae8, 0xaf0, 0xaf8, 0xb00, 0xb08, 0xb10,
		0xb18, 0xb20, 0xb28, 0xb48, 0xb50, 0xb58, 0xb60, 0xb68, 0xb70, 0xb78,
		0xb80, 0xb88, 0xb90, 0xb98, 0xba0, 0xba8, 0xbb0, 0xbb8, 0xbc0, 0xbc8,
		0xbd0, 0xbd8, 0xbe0, 0xbe8, 0xbf0, 0xbf8, 0xc00, 0xc08, 0xc10, 0xc18,
		0xcc8, 0xa48, 0xc60
	};
#elif defined LINUX_VER_3_10_0
	// 0x758 for 3.10.0-957, 3.10.0-1160 
	int files_offset_array[] = { 0x758 };
#else
	// 0xd08 for kernel-devel-4.19.91-26.6.al7, 4.19.91-27.1.al7.x86_64
	// 0x740 for 4.19.113-300.el7.x86_64
	// 0x6c0 for 4.19.0-25-amd64 #1 SMP Debian 4.19.289-2 (2023-08-08)
	// 0x7b0 for 4.19.91-21.al7.x86_64, 4.19.91-23.al7.x86_64
	// 0xcc8 for 4.19.91-26.1.al7.x86_64, 4.19.91-26.al7.x86_64
	// 0xb70 for 4.19.91-24.1.al7.x86_64
	// 0xbb0 for 4.19.91-25.6.al7.x86_64
	// 0x6b8 for 4.19.117.business.1-amd64
	// 0xb88 for 4.19.0-91.77.112.uelc20.x86_64, 4.19.0-91.82.65.uelc20.x86_64
	int files_offset_array[] = {
		0x6c0, 0x790, 0x7b0, 0xa80, 0xa88, 0xaa0, 0xaa8, 0xab0, 0xab8, 0xac0,
		0xac8, 0xad0, 0xad8, 0xae0, 0xae8, 0xaf0, 0xaf8, 0xb00, 0xb08, 0xb10,
		0xb18, 0xb20, 0xb48, 0xb50, 0xb58, 0xb60, 0xb68, 0xb70, 0xb78, 0xb90,
		0xb98, 0xba0, 0xbb0, 0x740, 0xbc0, 0xbc8, 0xbd0, 0xbd8, 0xbe0, 0xbe8,
		0xbf0, 0xbf8, 0xc00, 0xc08, 0xcc8, 0xd08, 0x6b8, 0xb88
	};
#endif
/* *INDENT-ON* */

	if (unlikely(!offset->task__files_offset)) {
#pragma unroll
		for (i = 0; i < ARRAY_SIZE(files_offset_array); i++) {
			file =
			    retry_get_socket_file_addr(task, fd_num,
						       offset->struct_files_struct_fdt_offset,
						       files_offset_array[i]);

			if (file) {
				bpf_probe_read_kernel(&private_data,
						      sizeof(private_data),
						      file +
						      offset->struct_files_private_data_offset);
				if (private_data != NULL) {
					socket = private_data;
					bpf_probe_read_kernel(&__socket,
							      sizeof(__socket),
							      (void *)socket);
					if (__socket.file == file
					    || file == __socket.wq) {
						offset->task__files_offset =
						    files_offset_array[i];
						break;
					}
				}
			}
		}
	} else {
		file =
		    retry_get_socket_file_addr(task, fd_num,
					       offset->struct_files_struct_fdt_offset,
					       offset->task__files_offset);
	}

	if (file == NULL || !offset->task__files_offset) {
		return NULL;
	}

	bpf_probe_read_kernel(&private_data, sizeof(private_data),
			      file + offset->struct_files_private_data_offset);

	if (private_data == NULL) {
		return NULL;
	}

	socket = private_data;
	short socket_type;
	void *check_file;
	void *sk;
	bpf_probe_read_kernel(&__socket, sizeof(__socket), (void *)socket);
	socket_type = __socket.type;
	if (__socket.file != file) {
		check_file = __socket.wq;	// kernel >= 5.3.0 remove '*wq'
		sk = __socket.file;
	} else {
		check_file = __socket.file;
		sk = __socket.sk;
	}

	if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) &&
	    check_file == file /*&& __socket.state == SS_CONNECTED */ ) {
		return sk;
	}

	return NULL;
}

static __inline void *get_socket_from_fd(int fd_num,
					 struct member_fields_offset *offset)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	void *file = NULL;
	file =
	    get_socket_file_addr_with_check(task, fd_num,
					    offset->task__files_offset,
					    offset->
					    struct_files_struct_fdt_offset);
	if (file == NULL)
		return NULL;
	void *private_data = NULL;

	bpf_probe_read_kernel(&private_data, sizeof(private_data),
			      file + offset->struct_files_private_data_offset);
	if (private_data == NULL) {
		return NULL;
	}

	struct socket *socket = private_data;
	short socket_type;
	void *check_file;
	void *sk;
	struct socket __socket;
	bpf_probe_read_kernel(&__socket, sizeof(__socket), (void *)socket);

	socket_type = __socket.type;
	if (__socket.file != file) {
		check_file = __socket.wq;	// kernel >= 5.3.0 remove '*wq'
		sk = __socket.file;
	} else {
		check_file = __socket.file;
		sk = __socket.sk;
	}
	if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) &&
	    check_file == file /*&& __socket.state == SS_CONNECTED */ ) {
		return sk;
	}

	return NULL;
}

static __inline void *fd_to_file(int fd_num,
				 struct member_fields_offset *offset)
{
	if (!offset) {
		return NULL;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	void *file =
	    get_socket_file_addr_with_check(task, fd_num,
					    offset->task__files_offset,
					    offset->
					    struct_files_struct_fdt_offset);
	return file;
}

static __inline __u32 file_to_i_mode(void *file,
				     struct member_fields_offset *offset)
{
	if (!file) {
		return 0;
	}

	void *f_inode = NULL;

	bpf_probe_read_kernel(&f_inode, sizeof(f_inode),
			      file + offset->struct_file_f_inode_offset);

	if (!f_inode) {
		return 0;
	}

	__u32 i_mode = 0;

	bpf_probe_read_kernel(&i_mode, sizeof(i_mode),
			      f_inode + offset->struct_inode_i_mode_offset);

	return i_mode;
}

static __inline char *file_to_name(void *file,
				   struct member_fields_offset *offset)
{
	if (!file) {
		return 0;
	}

	void *dentry = NULL;
	bpf_probe_read_kernel(&dentry, sizeof(dentry),
			      file + offset->struct_file_dentry_offset);

	if (!dentry) {
		return 0;
	}

	char *name = NULL;
	bpf_probe_read_kernel(&name, sizeof(name),
			      dentry + offset->struct_dentry_name_offset);
	return name;
}

#endif /* DF_TASK_STRUCT_UTILS_H */
