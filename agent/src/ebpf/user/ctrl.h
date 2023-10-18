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

#ifndef __CTRL_H__
#define __CTRL_H__
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "common.h"
#include "list.h"

#define UNIX_DOMAIN_DEF "/var/run/deepflow_bpf_ctrl"

typedef uint32_t sockoptid_t;

#define SOCKOPT_VERSION_MAJOR   1
#define SOCKOPT_VERSION_MINOR   0
#define SOCKOPT_VERSION_PATCH   0
#define SOCKOPT_VERSION     ((SOCKOPT_VERSION_MAJOR << 16) + \
          (SOCKOPT_VERSION_MINOR << 8) + SOCKOPT_VERSION_PATCH)

#define SOCKOPT_ERRSTR_LEN  64

enum sockopt_type {
	SOCKOPT_GET = 0,
	SOCKOPT_SET,
	SOCKOPT_TYPE_MAX,
};

struct tracer_sock_msg {
	uint32_t version;
	sockoptid_t id;
	enum sockopt_type type;
	size_t len;
	char data[0];
};

struct tracer_sockopts {
	uint32_t version;
	struct list_head list;
	sockoptid_t set_opt_min;
	sockoptid_t set_opt_max;
	int (*set) (sockoptid_t opt, const void *in, size_t inlen);
	sockoptid_t get_opt_min;
	sockoptid_t get_opt_max;
	int (*get) (sockoptid_t opt, const void *in, size_t inlen, void **out,
		    size_t * outlen);
};

struct tracer_sock_msg_reply {
	uint32_t version;
	sockoptid_t id;
	enum sockopt_type type;
	int errcode;
	char errstr[SOCKOPT_ERRSTR_LEN];
	size_t len;
	char data[0];
};

struct datadump_msg {
	bool enable;		// Whether to enable the datadump ?
	bool is_params;		// Is it set pid or comm ?
	bool only_stdout;	// Whether to dump data to stdout ?
	int timeout;
	int pid;
	uint8_t proto;
	char comm[16];
};

struct cpdbg_msg {
	bool enable;		// Whether to enable the datadump ?
	int timeout;
};

int sockopt_ctl(void *arg);
int ctrl_init(void);
int sockopt_register(struct tracer_sockopts *sockopts);
int sockopt_unregister(struct tracer_sockopts *sockopts);
ssize_t sendn(int fd, const void *vptr, size_t n, int flags);
ssize_t readn(int fd, void *vptr, size_t n);
#endif /*__CTRL_H__*/
