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

#ifndef DF_JAVA_CONFIG_H
#define DF_JAVA_CONFIG_H

// Maximum length of Java symbol information string
#define STRING_BUFFER_SIZE 2048
/*
 * In Unix domain sockets, the maximum length of the path is defined by
 * the macro UNIX_PATH_MAX. For most systems (e.g., Linux), this maximum
 * length is typically 108 characters. 
 */
#define UNIX_PATH_MAX 108

// The upper limit for updating Java symbol files during method unload events.
#define UPDATE_SYMS_FILE_UNLOAD_HIGH_THRESH 100

enum event_type {
	METHOD_LOAD,
	METHOD_UNLOAD,
	DYNAMIC_CODE_GEN
};

struct symbol_metadata {
	unsigned short len;
	unsigned short type;
};

#define TARGET_NS_STORAGE_PATH "/proc/%d/root/deepflow"

#if !defined(AGENT_LIB_NAME) || !defined(AGENT_MUSL_LIB_NAME)
#error Makefile should define "AGENT_LIB_NAME" and "AGENT_MUSL_LIB_NAME"
#endif

#define AGENT_LIB_SRC_PATH "/tmp/" AGENT_LIB_NAME
#define AGENT_LIB_TARGET_PATH "/deepflow/" AGENT_LIB_NAME

#define AGENT_MUSL_LIB_SRC_PATH "/tmp/" AGENT_MUSL_LIB_NAME
#define AGENT_MUSL_LIB_TARGET_PATH "/deepflow/" AGENT_MUSL_LIB_NAME

#define JAVA_LOG_TAG "[JAVA] "

#define PERF_PATH_SZ 256
#define DF_AGENT_MAP_SOCKET_PATH_FMT "/proc/%d/root/tmp/.deepflow-java-symbols-pid%d.socket"
#define DF_AGENT_LOG_SOCKET_PATH_FMT "/proc/%d/root/tmp/.deepflow-java-jvmti-logs-pid%d.socket"

#define DF_AGENT_LOCAL_PATH_FMT "/tmp/perf-%d"

#define JVM_AGENT_SYMS_SOCKET_PATH_FMT "/tmp/.deepflow-java-symbols-pid%d.socket"
#define JVM_AGENT_LOG_SOCKET_PATH_FMT "/tmp/.deepflow-java-jvmti-logs-pid%d.socket"

#endif /* DF_JAVA_CONFIG_H */
