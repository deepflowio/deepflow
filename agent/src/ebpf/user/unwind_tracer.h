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

#ifndef _UNWIND_TRACER_H_
#define _UNWIND_TRACER_H_

#include "tracer.h"
#include "profile/profile_common.h"

// Scan /proc/ to get all processes when the agent starts
int unwind_tracer_init(struct bpf_tracer *tracer);

void unwind_tracer_drop();

// Get the process creation event and put the event into the queue
void unwind_process_exec(int pid);

// Process events in the queue
void unwind_events_handle(void);

// Process exit, reclaim resources
void unwind_process_exit(int pid);

// Trigger a unwind table reload, used on enabling DWARF or setting matching regular expressions
void unwind_process_reload();

// Configuration related functions
bool get_dwarf_enabled(void);
void set_dwarf_enabled(bool enabled);
int get_dwarf_process_map_size(void);
int get_dwarf_shard_map_size(void);

#endif
