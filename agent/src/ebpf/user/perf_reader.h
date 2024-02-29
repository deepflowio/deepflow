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

#include <sys/epoll.h>
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

static inline int
__reader_epoll_wait(struct bpf_perf_reader *r,
		    struct epoll_event *events,
		    int epoll_id, int timeout)
{
	int nfds = epoll_wait(r->epoll_fds[epoll_id], events,
			      r->readers_count, timeout);
	if (nfds == -1) {
		ebpf_warning("epoll_wait() failed\n");
		return ETR_EPOLL;
        }

	return nfds;
}

static inline int
reader_epoll_wait(struct bpf_perf_reader *r,
		  struct epoll_event *events,
		  int epoll_id)
{
	return __reader_epoll_wait(r, events, epoll_id,
				   r->epoll_timeout);
}

static inline bool
reader_epoll_short_wait(struct bpf_perf_reader *r,
			struct epoll_event *events,
			int epoll_id)
{
	return __reader_epoll_wait(r, events, epoll_id,
				   EPOLL_SHORT_TIMEOUT);
}

static inline void
reader_event_read(struct epoll_event *events,
		  int nfds)
{
	int i;
	for (i = 0; i < nfds; ++i) {
		perf_reader_event_read(events[i].data.ptr);
	}
}

static inline void
reader_event_read_polling(struct epoll_event *events,
			  int nfds)
{
	int i;
	for (i = 0; i < nfds; ++i) {
		perf_reader_event_read(events[i].data.ptr);
	}
}

#endif /* _BPF_PERF_READER_H_ */
