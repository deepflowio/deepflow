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

#ifndef __INCLUDE_LOG_H__
#define __INCLUDE_LOG_H__

#include <linux/errno.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>

#ifndef HAVE_ERRNO
#define HAVE_ERRNO
#endif

#define MSG_SZ 2048

// 日志文件地址
extern FILE *log_stream;
// 日志是否输出到标准输出
extern bool log_to_stdout;

enum
{
	ERROR_FATAL = 1 << 0,
	ERROR_ABORT = 1 << 1,
	ERROR_WARNING = 1 << 2,
	ERROR_ERRNO_VALID = 1 << 16,
	ERROR_NO_RATE_LIMIT = 1 << 17,
};

/* Current function name.  Need (char *) cast to silence gcc4 pointer signedness warning. */
#define ebpf_error_function ((char *) __FUNCTION__)
#define ebpf_error_file ((char *) __FILE__)

#ifdef BPF_DEBUG
#define ebpf_debug(fmt, ...)  printf(fmt, ##__VA_ARGS__);
#else
#define ebpf_debug(fmt, ...)
#endif

#define ebpf_info(format,args...) \
	_ebpf_info (format, ## args)

#define ebpf_warning(format,args...) \
	_ebpf_error (ERROR_WARNING, ebpf_error_function, ebpf_error_file, __LINE__, format, ## args)

#define ebpf_error(format,args...) \
	_ebpf_error (ERROR_ABORT, ebpf_error_function, ebpf_error_file, __LINE__, format, ## args)

void _ebpf_error(int how_to_die,
                 char *function_name,
		 char *file_path,
                 uint32_t line_number,
                 char *fmt, ...);
void _ebpf_info(char *fmt, ...);
#endif
