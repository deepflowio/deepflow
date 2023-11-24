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

#ifndef GEN_SYMS_FILE_H
#define GEN_SYMS_FILE_H

#define DF_JAVA_ATTACH_CMD "/usr/bin/deepflow-jattach"

struct java_syms_update_task {
	struct list_head list;
	struct symbolizer_proc_info *p;
};

void gen_java_symbols_file(int pid, bool *need_update);
void clean_local_java_symbols_files(int pid);
void add_java_syms_update_task(struct symbolizer_proc_info *p_info);
void java_syms_update_main(void *arg);
#endif /* GEN_SYMS_FILE_H */
