/*
 * Copyright (c) 2023 Yunshan Networks
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

#ifndef DF_JATTACH_H
#define DF_JATTACH_H

#define AGENT_LIB_NAME "df_java_agent.so"
#define AGENT_LIB_SRC_PATH "/tmp/" AGENT_LIB_NAME

#define AGENT_MUSL_LIB_NAME "df_java_agent_musl.so"
#define AGENT_MUSL_LIB_SRC_PATH "/tmp/" AGENT_MUSL_LIB_NAME

#define JAVA_LOG_TAG "[JAVA]"

typedef uint64_t(*agent_test_t) (void);

void clear_target_ns_tmp_file(const char *target_path);
void copy_file_from_target_ns(int pid, int ns_pid, const char *file_type);
void clear_target_ns(int pid, int target_ns_pid);
void clear_target_ns_so(int pid, int target_ns_pid);
#endif /* DF_JATTACH_H */
