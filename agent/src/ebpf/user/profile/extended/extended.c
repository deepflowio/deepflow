/*
 * Copyright (c) 2024 Yunshan Networks
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

#include <sys/stat.h>
#include <bcc/perf_reader.h>
#include "../../config.h"
#include "../../utils.h"
#include "../../common.h"
#include "../../mem.h"
#include "../../log.h"
#include "../../types.h"
#include "../../vec.h"
#include "../../tracer.h"
#include "../../socket.h"

int __attribute__ ((weak)) extended_reader_create(struct bpf_tracer *tracer)
{
	return 0;
}

int __attribute__ ((weak)) extended_maps_set(struct bpf_tracer *tracer)
{
	return 0;
}

int __attribute__ ((weak)) extended_proc_event_handler(int pid,
						       const char *name,
						       enum proc_act_type type)
{
	return 0;
}

void __attribute__ ((weak)) extended_print_cp_tracer_status(void)
{
}

int __attribute__ ((weak)) set_socket_fanout_ebpf(int socket, int group_id)
{
	return 0;
}
