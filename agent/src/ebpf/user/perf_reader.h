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

#ifndef _BPF_PERF_READER_H_
#define _BPF_PERF_READER_H_

#include <poll.h>
#include <bcc/perf_reader.h>

struct perf_reader {
	void *raw_cb;
	void *lost_cb;
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

static inline bool
reader_poll_wait(struct bpf_perf_reader *r, struct pollfd *pfds)
{
	int i;
	for (i = 0; i < r->readers_count; ++i) {
		pfds[i].fd = r->readers[i]->fd;
		pfds[i].events = POLLIN;
	}

	return (poll(pfds, r->readers_count, r->poll_timeout) > 0);
}

static inline void
reader_event_read(struct bpf_perf_reader *r, struct pollfd *pfds)
{
	int i;
	for (i = 0; i < r->readers_count; ++i) {
		if (pfds[i].revents & POLLIN)
			perf_reader_event_read(r->readers[i]);
	}
}

#endif /* _BPF_PERF_READER_H_ */
