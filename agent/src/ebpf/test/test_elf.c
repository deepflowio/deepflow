/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <limits.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>		//PATH_MAX(4096)
#include <arpa/inet.h>
#include <memory.h>
#include <bcc/linux/bpf.h>
#include <bcc/linux/bpf_common.h>
#include "../user/socket_trace_bpf_core.c"
#include "../user/common.h"
#include "../user/log.h"
#include "../user/elf.h"
#include "../user/load.h"
#include "../user/btf_vmlinux.h"

int main(void)
{
	log_to_stdout = true;	
	void *bpf_bin_buffer = (void *)socket_trace_core_ebpf_data;
	int buffer_sz = sizeof(socket_trace_core_ebpf_data);
	struct ebpf_object *obj = ebpf_open_buffer(bpf_bin_buffer, buffer_sz, "xxxx");		
	ebpf_obj_load(obj);
	int offset;
	offset = kernel_struct_field_offset(obj, "tcp_sock", "copied_seq");
	printf("--- struct tcp_sock->copied_seq %x\n", offset);

        offset = kernel_struct_field_offset(obj, "tcp_sock", "write_seq");
        printf("--- struct tcp_sock->write_seq %x\n", offset);

        offset = kernel_struct_field_offset(obj, "task_struct", "files");
        printf("--- struct task_struct->files %x\n", offset);

        offset = kernel_struct_field_offset(obj, "sock", "__sk_flags_offset");
        printf("--- struct sock->__sk_flags_offset %x\n", offset);

	for(;;)
		sleep(1);

	return 0;
}
