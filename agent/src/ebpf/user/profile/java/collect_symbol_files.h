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

#ifndef COLLECT_SYMS_FILE_H
#define COLLECT_SYMS_FILE_H

#define JAVA_SYMS_COLLECT_OK		0
#define JAVA_SYMS_COLLECT_ERR		1
#define JAVA_CREATE_COLLECTOR_ERR	2
#define JAVA_SYMS_NEED_UPDATE		3
#define JAVA_SYMS_NEW_COLLECTOR		4

struct java_syms_update_task {
	struct list_head list;
	struct symbolizer_proc_info *p;
};

void gen_java_symbols_file(int pid, int *ret_val, bool error_occurred);
void clean_local_java_symbols_files(int pid);
void add_java_syms_update_task(struct symbolizer_proc_info *p_info);
void java_syms_update_main(void *arg);
#endif /* COLLECT_SYMS_FILE_H */
