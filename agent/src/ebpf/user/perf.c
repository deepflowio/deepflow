/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "perf.h"
#include "log.h"

extern int ioctl(int fd, unsigned long request, ...);

enum {
	RB_NOT_USED = 0,	// ring buffer not usd
	RB_USED_IN_MUNMAP = 1,	// used in munmap
	RB_USED_IN_READ = 2,	// used in read
};

#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)
#endif

static struct perf_reader *perf_reader_new(perf_reader_raw_cb raw_cb,
					   perf_reader_lost_cb lost_cb,
					   void *cb_cookie, int page_cnt)
{
	struct perf_reader *reader = calloc(1, sizeof(struct perf_reader));
	if (!reader)
		return NULL;
	reader->raw_cb = raw_cb;
	reader->lost_cb = lost_cb;
	reader->cb_cookie = cb_cookie;
	reader->fd = -1;
	reader->page_size = getpagesize();
	reader->page_cnt = page_cnt;
	return reader;
}

static void perf_reader_set_fd(struct perf_reader *reader, int fd)
{
	reader->fd = fd;
}

static int perf_reader_mmap(struct perf_reader *reader)
{
	int mmap_size = reader->page_size * (reader->page_cnt + 1);

	if (reader->fd < 0) {
		ebpf_info("%s: reader fd is not set\n", __FUNCTION__);
		return -1;
	}

	reader->base =
	    mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		 reader->fd, 0);
	if (reader->base == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	return 0;
}

static void perf_reader_free(void *ptr)
{
	if (ptr) {
		struct perf_reader *reader = ptr;
		pid_t tid = syscall(__NR_gettid);
		while (!__sync_bool_compare_and_swap
		       (&reader->rb_use_state, RB_NOT_USED,
			RB_USED_IN_MUNMAP)) {
			// If the same thread, it is called from call back handler, no locking needed
			if (tid == reader->rb_read_tid)
				break;
		}
		munmap(reader->base,
		       reader->page_size * (reader->page_cnt + 1));
		if (reader->fd >= 0) {
			ioctl(reader->fd, PERF_EVENT_IOC_DISABLE, 0);
			close(reader->fd);
		}
		free(reader->buf);
		free(ptr);
	}
}

void *bpf_open_perf_buffer(perf_reader_raw_cb raw_cb,
			   perf_reader_lost_cb lost_cb, void *cb_cookie,
			   int pid, int cpu, int page_cnt)
{
	int pfd;
	struct perf_event_attr attr = {};
	struct perf_reader *reader = NULL;
	reader = perf_reader_new(raw_cb, lost_cb, cb_cookie, page_cnt);
	if (!reader) {
		ebpf_info("perf_reader_mmap error\n");
		goto error;
	}

	attr.config = 10;	//PERF_COUNT_SW_BPF_OUTPUT;
	attr.type = PERF_TYPE_SOFTWARE;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	pfd =
	    syscall(__NR_perf_event_open, &attr, pid, cpu, -1,
		    PERF_FLAG_FD_CLOEXEC);
	if (pfd < 0) {
		ebpf_info("perf_event_open: %s\n", strerror(errno));
		goto error;
	}
	perf_reader_set_fd(reader, pfd);

	if (perf_reader_mmap(reader) < 0)
		goto error;

	if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
		perror("ioctl(PERF_EVENT_IOC_ENABLE)");
		goto error;
	}

	return reader;

error:
	if (reader)
		perf_reader_free(reader);

	return NULL;
}

static void parse_sw(struct perf_reader *reader, void *data, int size)
{
	uint8_t *ptr = data;
	struct perf_event_header *header = (void *)data;

	struct {
		uint32_t size;
		char data[0];
	} *raw = NULL;

	ptr += sizeof(*header);
	if (ptr > (uint8_t *) data + size) {
		ebpf_info("%s: corrupt sample header\n", __FUNCTION__);
		return;
	}

	raw = (void *)ptr;
	ptr += sizeof(raw->size) + raw->size;
	if (ptr > (uint8_t *) data + size) {
		ebpf_info("%s: corrupt raw sample\n", __FUNCTION__);
		return;
	}
	// sanity check
	if (ptr != (uint8_t *) data + size) {
		ebpf_info("%s: extra data at end of sample\n",
			__FUNCTION__);
		return;
	}

	if (reader->raw_cb)
		reader->raw_cb(reader->cb_cookie, raw->data, raw->size);
}

static uint64_t read_data_head(volatile struct perf_event_mmap_page
			       *perf_header)
{
	uint64_t data_head = perf_header->data_head;
	asm volatile ("":::"memory");
	return data_head;
}

static void write_data_tail(volatile struct perf_event_mmap_page *perf_header,
			    uint64_t data_tail)
{
	asm volatile ("":::"memory");
	perf_header->data_tail = data_tail;
}

static void perf_reader_event_read(struct perf_reader *reader)
{

	volatile struct perf_event_mmap_page *perf_header = reader->base;
	uint64_t buffer_size = (uint64_t) reader->page_size * reader->page_cnt;
	uint64_t data_head;
	uint8_t *base = (uint8_t *) reader->base + reader->page_size;
	uint8_t *sentinel =
	    (uint8_t *) reader->base + buffer_size + reader->page_size;
	uint8_t *begin, *end;
	reader->rb_read_tid = syscall(__NR_gettid);
	if (!__sync_bool_compare_and_swap
	    (&reader->rb_use_state, RB_NOT_USED, RB_USED_IN_READ))
		return;

	// Consume all the events on this ring, calling the cb function for each one.
	// The message may fall on the ring boundary, in which case copy the message
	// into a malloced buffer.
	for (data_head = read_data_head(perf_header);
	     perf_header->data_tail != data_head;
	     data_head = read_data_head(perf_header)) {
		uint64_t data_tail = perf_header->data_tail;
		uint8_t *ptr;

		begin = base + data_tail % buffer_size;
		// event header is u64, won't wrap
		struct perf_event_header *e = (void *)begin;
		ptr = begin;
		end = base + (data_tail + e->size) % buffer_size;
		if (end < begin) {
			// perf event wraps around the ring, make a contiguous copy
			reader->buf = realloc(reader->buf, e->size);
			size_t len = sentinel - begin;
			memcpy(reader->buf, begin, len);
			memcpy((void *)((unsigned long)reader->buf + len), base,
			       e->size - len);
			ptr = reader->buf;
		}

		if (e->type == PERF_RECORD_LOST) {
			uint64_t lost =
			    *(uint64_t *) (ptr + sizeof(*e) + sizeof(uint64_t));
			if (reader->lost_cb) {
				reader->lost_cb(reader->cb_cookie, lost);
			} else {
				ebpf_info("Possibly lost %" PRIu64 " samples\n",
					  lost);
			}
		} else if (e->type == PERF_RECORD_SAMPLE) {
			parse_sw(reader, ptr, e->size);
		} else {
			ebpf_info("%s: unknown sample type %d\n",
				__FUNCTION__, e->type);
		}

		write_data_tail(perf_header, perf_header->data_tail + e->size);
	}
	reader->rb_use_state = RB_NOT_USED;
	__sync_synchronize();
	reader->rb_read_tid = 0;
}

int perf_reader_poll(int num_readers, struct perf_reader **readers, int timeout)
{
	struct pollfd pfds[num_readers];
	int i;

	for (i = 0; i < num_readers; ++i) {
		pfds[i].fd = readers[i]->fd;
		pfds[i].events = POLLIN;
	}

	if (poll(pfds, num_readers, timeout) > 0) {
		for (i = 0; i < num_readers; ++i) {
			if (pfds[i].revents & POLLIN)
				perf_reader_event_read(readers[i]);
		}
	}

	return 0;
}
