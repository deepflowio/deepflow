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

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/uio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include "log.h"

FILE *log_stream;
bool log_to_stdout;

void os_panic(void) __attribute__ ((weak));

void os_panic(void)
{
	abort();
}

void os_exit(int) __attribute__ ((weak));

void os_exit(int code)
{
	exit(code);
}

void os_puts(FILE *stream, char *string, uint32_t string_length, bool is_stdout)
{
	int fd;
	struct iovec iovs[2];
	int n_iovs = 0;

	iovs[n_iovs].iov_base = string;
	iovs[n_iovs].iov_len = string_length;
	n_iovs++;

	if (is_stdout) {
		writev(1, iovs, n_iovs);
		fflush(stdout);
	}

	if (!stream)
		return;

	fd = fileno(stream);
	writev(fd, iovs, n_iovs);
}

static void debugger(void)
{
	os_panic();
}

static void error_exit(int code)
{
	os_exit(code);
}

extern void rust_info_wrapper(char *msg);

__attribute__((weak)) void rust_info_wrapper(char *msg)
{
	printf("%s\n", msg);
}

static char *dispatch_message(char *msg, uint16_t len)
{
	if (!msg || len < 1)
		return msg;

	if (msg[len - 1] == '\n')
		msg[len - 1] = 0;
	rust_info_wrapper(msg);
	return msg;
}

void _ebpf_error(int how_to_die, char *function_name, char *file_path,
		 uint32_t line_number, char *fmt, ...)
{
	char msg[MSG_SZ] = {};
	uint16_t len = 0;
	uint16_t max = MSG_SZ;
	va_list va;

	if (function_name) {
		if (how_to_die & ERROR_WARNING) {
			len += snprintf(msg + len, max - len, "[eBPF] WARNING: func %s()", function_name);
		} else {
			len += snprintf(msg + len, max - len, "[eBPF] ERROR: func %s()", function_name);
		}
		if (line_number > 0)
			len +=
			    snprintf(msg + len, max - len, " [%s:%u] ",
				     file_path, line_number);
	}
#ifdef HAVE_ERRNO
	if (how_to_die & ERROR_ERRNO_VALID)
		len += snprintf(msg + len, max - len,
				": %s (errno %d)", strerror(errno), errno);
#endif
	va_start(va, fmt);
	len += vsnprintf(msg + len, max - len, fmt, va);
	va_end(va);

	dispatch_message(msg, len);
	if (how_to_die & ERROR_ABORT)
		debugger();

	if (how_to_die & ERROR_FATAL)
		error_exit(1);
}

void _ebpf_info(char *fmt, ...)
{
	char msg[MSG_SZ] = {};
	uint16_t len = 0;
	uint16_t max = MSG_SZ;
	va_list va;

	len += snprintf(msg + len, max - len, "[eBPF] INFO ");

	va_start(va, fmt);
	len += vsnprintf(msg + len, max - len, fmt, va);
	va_end(va);
	if (msg[len - 1] != '\n') {
		if (len < max)
			msg[len++] = '\n';
		else
			msg[len - 1] = '\n';
	}

	dispatch_message(msg, len);
}
