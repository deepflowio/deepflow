#ifndef _BPF_PERF_H_
#define _BPF_PERF_H_

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <syscall.h>
#include <poll.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <linux/perf_event.h>
#include "../libbpf/src/libbpf.h"
#include "../libbpf/src/bpf.h"

typedef void (*perf_reader_raw_cb) (void *cb_cookie, void *raw, int raw_size);
typedef void (*perf_reader_lost_cb) (void *cb_cookie, uint64_t lost);

struct perf_reader {
	perf_reader_raw_cb raw_cb;
	perf_reader_lost_cb lost_cb;
	void *cb_cookie;	// to be returned in the cb
	void *buf;		// for keeping segmented data
	size_t buf_size;
	void *base;
	int rb_use_state;
	pid_t rb_read_tid;
	int page_size;
	int page_cnt;
	int fd;
};

void *bpf_open_perf_buffer(perf_reader_raw_cb raw_cb,
			   perf_reader_lost_cb lost_cb, void *cb_cookie,
			   int pid, int cpu, int page_cnt);

int perf_reader_poll(int num_readers, struct perf_reader **readers,
		     int timeout);
#endif
