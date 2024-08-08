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

#ifndef DF_EXTENDED_H
#define DF_EXTENDED_H

/**
 * @brief **extended_reader_create()** create an extended reader to
 * receive perfbuf data.
 *
 * You can rewrite the extended_reader_create() function to expand
 * the functionality of other function stack profiling. Inside it,
 * you can append new readers to read data from the eBPF perfbuf
 * and enable new threads to handle the reception.
 *
 * @param tracer BPF tracer address
 * @return 0 on success, non-zero on error
 */
int extended_reader_create(struct bpf_tracer *tracer);
int extended_maps_set(struct bpf_tracer *tracer);

/**
 * @brief **extended_proc_event_handler()** extend the handling of process
 * execution and exit events.
 * @param pid Process ID
 * @param name Process name
 * @param PROC_EXEC or PROC_EXIT
 * @return 0 on success, non-zero on error
 *
 * For example, you might want to notify an eBPF program of these events
 * so that eBPF can perform the corresponding handling. Extend the handling
 * based on your own requirements.
 */
int extended_proc_event_handler(int pid, const char *name,
				enum proc_act_type type);

/**
 * @brief **collect_extended_uprobe_syms_from_procfs()** extend the handling of uprobe
 * @param conf Tracer probes config
 * @return 0 on success, non-zero on error
 */
int collect_extended_uprobe_syms_from_procfs(struct tracer_probes_conf *conf);

/**
 * @brief **extended_process_exec()** get the process creation event and put the event into the queue
 * @param pid Process ID
 */
void extended_process_exec(int pid);

/**
 * @brief **extended_events_handle()** process events in the queue
 */
void extended_events_handle(void);

/**
 * @brief **extended_process_exit()** process exit, reclaim resources
 * @param pid Process ID
 */
void extended_process_exit(int pid);

#endif /* DF_EXTENDED_H */
