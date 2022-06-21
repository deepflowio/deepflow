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

#define ebpf_info(format,args...) \
	_ebpf_info (format, ## args)

#define ebpf_warning(format,args...) \
	_ebpf_error (ERROR_WARNING, ebpf_error_function, __LINE__, format, ## args)

void _ebpf_error(int how_to_die,
                 char *function_name,
                 uint32_t line_number,
                 char *fmt, ...);
void _ebpf_info(char *fmt, ...);
#endif
