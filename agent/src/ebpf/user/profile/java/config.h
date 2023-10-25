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

#ifndef DF_JAVA_CONFIG_H
#define DF_JAVA_CONFIG_H

#define TARGET_NS_STORAGE_PATH "/proc/%d/root/deepflow"

#define AGENT_LIB_NAME "df_java_agent.so"
#define AGENT_LIB_SRC_PATH "/tmp/" AGENT_LIB_NAME
#define AGENT_LIB_TARGET_PATH "/deepflow/" AGENT_LIB_NAME

#define AGENT_MUSL_LIB_NAME "df_java_agent_musl.so"
#define AGENT_MUSL_LIB_SRC_PATH "/tmp/" AGENT_MUSL_LIB_NAME
#define AGENT_MUSL_LIB_TARGET_PATH "/deepflow/" AGENT_MUSL_LIB_NAME

#define JAVA_LOG_TAG "[JAVA]"

#define PERF_PATH_SZ 256
#define DF_AGENT_MAP_PATH_FMT "/proc/%d/root/deepflow/df-perf-%d.map"
#define DF_AGENT_LOG_PATH_FMT "/proc/%d/root/deepflow/df-perf-%d.log"

#define DF_AGENT_PATH_FMT "/proc/%d/root/deepflow/df-perf-%d"
#define DF_AGENT_LOCAL_PATH_FMT "/tmp/perf-%d"

#define PERF_MAP_FILE_FMT "/deepflow/df-perf-%d.map"
#define PERF_MAP_LOG_FILE_FMT "/deepflow/df-perf-%d.log"

#endif /* DF_JAVA_CONFIG_H */
