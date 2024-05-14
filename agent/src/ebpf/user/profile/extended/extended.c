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

/*
 * You can rewrite the extended_reader_create() function to expand
 * the functionality of other function stack profiling. Inside it,
 * you can append new readers to read data from the eBPF perfbuf
 * and enable new threads to handle the reception.
 */
int __attribute__ ((weak)) extended_reader_create(struct bpf_tracer *tracer)
{
	return 0;
}
