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

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <getopt.h>
#include "tracer.h"
#include "socket.h"

#define MFBPF_NAME           "deepflow-ebpfctl"
#define MFBPF_VERSION        "v1.0.0"
#define LINUX_VER_LEN        128

typedef enum mfbpf_cmd_e {
	MFBPF_CMD_ADD,
	MFBPF_CMD_DEL,
	MFBPF_CMD_SET,
	MFBPF_CMD_SHOW,
	MFBPF_CMD_REPLACE,
	MFBPF_CMD_FLUSH,
	MFBPF_CMD_HELP,
} mfbpf_cmd_t;

struct mfbpf_conf {
	int af;
	int verbose;
	int stats;
	int interval;
	int count;
	bool color;
	char *obj;
	mfbpf_cmd_t cmd;
	int argc;
	char **argv;
};

struct mfbpf_obj {
	char *name;
	void *param;

	void (*help) (void);
	/* @conf is used to passing general config like af, verbose, ...
	 * we have obj.parse() to handle obj specific parameters. */
	int (*do_cmd) (struct mfbpf_obj * obj, mfbpf_cmd_t cmd,
		       struct mfbpf_conf * conf);
	/* the parser can be used to parse @conf into @param */
	int (*parse) (struct mfbpf_obj * obj, struct mfbpf_conf * conf);
	int (*check) (const struct mfbpf_obj * obj, mfbpf_cmd_t cmd);
};

static void tracer_help(void)
{
	fprintf(stderr, "Usage:\n" "    %s tracer show\n", MFBPF_NAME);
}

static void socktrace_help(void)
{
	fprintf(stderr, "Usage:\n" "    %s tracer show\n", MFBPF_NAME);
}

static inline char *get_proto_name(uint16_t proto_id)
{
	switch (proto_id) {
	case PROTO_HTTP1:
		return "HTTP";
	case PROTO_HTTP2:
		return "HTTP2";
	case PROTO_TLS_HTTP1:
		return "TLS_HTTP1";
	case PROTO_TLS_HTTP2:
		return "TLS_HTTP2";
	case PROTO_MYSQL:
		return "MySQL";
	case PROTO_DNS:
		return "DNS";
	case PROTO_REDIS:
		return "Redis";
	case PROTO_KAFKA:
		return "Kafka";
	case PROTO_MQTT:
		return "MQTT";
	case PROTO_DUBBO:
		return "Dubbo";
	case PROTO_POSTGRESQL:
		return "PgSQL";
	default:
		return "Unknown";
	}

	return "Unknown";
}

static void tracer_dump(struct bpf_tracer_param *param)
{
	struct bpf_tracer_param *btp = param;
	struct rx_queue_info *rx_q;
	printf("%-18s %s\n", "Tracer", btp->name);	//, sizeof(btp->name), "%s", t->name);
	printf("%-18s %s\n", "Bpf buffer", btp->bpf_load_name);
	printf("%-18s %d\n", "Workers", btp->dispatch_workers_nr);
	printf("%-18s %d\n", "Perf-Pages-Count", btp->perf_pg_cnt);
	printf("%-18s %" PRIu64 "\n", "Events Lost", btp->lost);
	printf("%-18s %d\n", "Probes Count", btp->probes_count);
	printf("%-18s %d [ 0 (TRACER_INIT), 1 (TRACER_RUNNING), "
	       "2 (TRACER_STOP) ]\n", "State", btp->state);
	printf("%-18s %d\n", "Adapt", btp->adapt_success);
	printf("%-18s %d\n", "data_limit_max", btp->data_limit_max);
	printf("\n-------------------- Queue ---------------------------\n");
	int j;
	uint64_t enqueue_nr, enqueue_lost, burst_count, heap_get_failed,
	    dequeue_nr;
	enqueue_nr = enqueue_lost = burst_count = heap_get_failed = dequeue_nr =
	    0;
	for (j = 0; j < btp->dispatch_workers_nr; j++) {
		rx_q = &btp->rx_queues[j];
		printf
		    ("worker %d for queue, de %" PRIu64 " en %" PRIu64 " lost %"
		     PRIu64 " alloc failed %" PRIu64 " burst %" PRIu64
		     " queue size %u cap %u\n", j, rx_q->dequeue_nr,
		     rx_q->enqueue_nr, rx_q->enqueue_lost, rx_q->heap_get_failed,
		     rx_q->burst_count, rx_q->queue_size, rx_q->ring_capacity);
		heap_get_failed += rx_q->heap_get_failed;
		dequeue_nr += rx_q->dequeue_nr;
		enqueue_nr += rx_q->enqueue_nr;
		enqueue_lost += rx_q->enqueue_lost;
		burst_count += rx_q->burst_count;
	}

	printf
	    ("\nSUM dequeue %" PRIu64 " enqueue %" PRIu64 " lost %" PRIu64
	     " alloc failed %" PRIu64 " burst count %" PRIu64 "\n", dequeue_nr,
	     enqueue_nr, enqueue_lost, heap_get_failed, burst_count);

	fflush(stdout);

	printf("\n-------------------- Protocol ------------------------\n");
	for (j = 0; j < PROTO_NUM; j++) {
		if (btp->proto_status[j] > 0) {
			printf("- %-10s(%d) %" PRIu64 "\n",
			       get_proto_name((uint16_t) j),
			       j,
			       btp->proto_status[j]);
		}
	}

	printf("\n");
}

static void offset_dump(int cpu, struct bpf_offset_param *param)
{
	printf("----------------------------------\n");
	printf("cpu: \t%d\n", cpu);
	printf("ready: \t%d\n", param->ready);
	printf("task__files_offset: \t0x%x\n", param->task__files_offset);
	printf("sock__flags_offset: \t0x%x\n", param->sock__flags_offset);
	printf("socket__has_wq_ptr: \t0x%x(no use)\n",
	       param->socket__has_wq_ptr);
	printf("tcp_sock__copied_seq_offset: \t0x%x\n",
	       param->tcp_sock__copied_seq_offset);
	printf("tcp_sock__write_seq_offset: \t0x%x\n\n",
	       param->tcp_sock__write_seq_offset);
}

static inline int msg_send(int clt_fd,
			   const struct tracer_sock_msg *hdr,
			   const char *data, int data_len)
{
	int len, res;

	if (!hdr) {
		fprintf(stderr, "[%s] empty socket msg header\n", __func__);
		return -1;
	}

	len = sizeof(struct tracer_sock_msg);
	res = sendn(clt_fd, hdr, len, MSG_NOSIGNAL);
	if (len != res) {
		fprintf(stderr,
			"[%s] socket msg header send error -- %d/%d sent\n",
			__func__, res, len);
		return -1;
	}

	if (data && data_len) {
		res = sendn(clt_fd, data, data_len, MSG_NOSIGNAL);
		if (data_len != res) {
			fprintf(stderr,
				"[%s] scoket msg body send error -- %d/%d sent\n",
				__func__, res, data_len);
			return -1;
		}
	}

	return 0;
}

static inline int msg_recv(int clt_fd, struct tracer_sock_msg_reply *reply_hdr,
			   void **out, size_t * out_len)
{
	void *msg = NULL;
	int len, res;

	if (!reply_hdr) {
		fprintf(stderr, "[%s] empty reply msg pointer\n", __func__);
		return -1;
	}

	if (out)
		*out = NULL;
	if (out_len)
		*out_len = 0;

	len = sizeof(struct tracer_sock_msg_reply);
	memset(reply_hdr, 0, len);
	res = readn(clt_fd, reply_hdr, len);
	if (len != res) {
		fprintf(stderr,
			"[%s] socket msg header recv error -- %d/%d recieved\n",
			__func__, res, len);
		return -1;
	}

	if (reply_hdr->errcode) {
		fprintf(stderr,
			"[%s] errcode set in socket msg#%d header: %s(%d)\n",
			__func__, reply_hdr->id, reply_hdr->errstr,
			reply_hdr->errcode);
		return reply_hdr->errcode;
	}

	if (reply_hdr->len > 0) {
		msg = malloc(reply_hdr->len);
		if (NULL == msg) {
			fprintf(stderr, "[%s] no memory\n", __func__);
			return -1;
		}

		res = readn(clt_fd, msg, reply_hdr->len);
		if (res != reply_hdr->len) {
			fprintf(stderr,
				"[%s] socket msg body recv error -- %d/%d recieved\n",
				__func__, res, (int)reply_hdr->len);
			free(msg);
			return -1;
		}
	}

	if (SOCKOPT_VERSION != reply_hdr->version) {
		fprintf(stderr, "[%s] socket msg version not match\n",
			__func__);
		if (reply_hdr->len > 0)
			free(msg);
		return -1;
	}

	if (out && out_len) {
		*out = msg;
		*out_len = reply_hdr->len;
	} else if (reply_hdr->len > 0) {
		free(msg);
		if (out)
			*out = NULL;
		if (out_len)
			*out_len = 0;
	}

	return 0;
}

int mfbpf_getsockopt(sockoptid_t cmd, const void *in, size_t in_len,
		     void **out, size_t * out_len)
{
	struct tracer_sock_msg *msg;
	struct tracer_sock_msg_reply reply_hdr;
	struct sockaddr_un clt_addr;
	int clt_fd;
	int res;
	size_t msg_len;

	if (NULL == out || NULL == out_len) {
		fprintf(stderr, "[%s] no pointer for info return\n", __func__);
		return -1;
	}
	*out = NULL;
	*out_len = 0;

	memset(&clt_addr, 0, sizeof(struct sockaddr_un));
	clt_addr.sun_family = AF_UNIX;
	strncpy(clt_addr.sun_path, UNIX_DOMAIN_DEF,
		sizeof(clt_addr.sun_path) - 1);

	msg_len = sizeof(struct tracer_sock_msg);
	msg = malloc(msg_len);
	if (NULL == msg) {
		fprintf(stderr, "[%s] no memory\n", __func__);
		return -1;
	}

	clt_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	res = connect(clt_fd, (struct sockaddr *)&clt_addr, sizeof(clt_addr));
	if (-1 == res) {
		fprintf(stderr, "[%s] scoket msg connection error: %s\n",
			__func__, strerror(errno));
		free(msg);
		return -1;
	}

	memset(msg, 0, msg_len);
	msg->version = SOCKOPT_VERSION;
	msg->id = cmd;
	msg->type = SOCKOPT_GET;
	msg->len = in_len;
	res = msg_send(clt_fd, msg, in, in_len);

	free(msg);
	msg = NULL;

	if (res) {
		close(clt_fd);
		return res;
	}

	res = msg_recv(clt_fd, &reply_hdr, out, out_len);
	if (res) {
		close(clt_fd);
		return res;
	}

	if (reply_hdr.errcode) {
		fprintf(stderr, "[%s] Server error: %s\n", __func__,
			reply_hdr.errstr);
		close(clt_fd);
		return reply_hdr.errcode;
	}

	close(clt_fd);
	return 0;
}

static inline void mfbpf_sockopt_msg_free(void *msg)
{
	free(msg);
	msg = NULL;
}

static inline void get_kernel_version(char *buf)
{
	int major, minor, patch;
	fetch_kernel_version(&major, &minor, &patch);
	snprintf(buf, LINUX_VER_LEN, "Linux %d.%d.%d\n", major, minor, patch);
}

static int socktrace_do_cmd(struct mfbpf_obj *obj, mfbpf_cmd_t cmd,
			    struct mfbpf_conf *conf)
{
	struct bpf_socktrace_params *sk_trace_params = NULL;
	struct bpf_offset_param_array *array = NULL;
	size_t size, i;
	int err;
	char linux_ver_str[LINUX_VER_LEN];
	memset((void *)linux_ver_str, 0, sizeof(linux_ver_str));
	get_kernel_version(linux_ver_str);
	printf("\n\033[0;33;mLinux Version: %s\033[0m\n", linux_ver_str);

	switch (conf->cmd) {
	case MFBPF_CMD_SHOW:
		err =
		    mfbpf_getsockopt(SOCKOPT_GET_SOCKTRACE_SHOW, NULL,
				     0, (void **)&sk_trace_params, &size);
		if (err != 0)
			return err;

		if (sk_trace_params == NULL)
			return ETR_INVAL;

		array = &sk_trace_params->offset_array;

		if (size < sizeof(*sk_trace_params)
		    || size != sizeof(*sk_trace_params) +
		    array->count * sizeof(struct bpf_offset_param)) {
			fprintf(stderr, "corrupted response.\n");
			mfbpf_sockopt_msg_free(sk_trace_params);
			return ETR_INVAL;
		}

		printf("kern_socket_map_max:\t%u\n",
		       sk_trace_params->kern_socket_map_max);
		printf("kern_socket_map_used:\t%u\n",
		       sk_trace_params->kern_socket_map_used);
		printf("kern_trace_map_max:\t%u\n",
		       sk_trace_params->kern_trace_map_max);
		printf("kern_trace_map_used:\t%u\n\n",
		       sk_trace_params->kern_trace_map_used);
		printf
		    ("tracer_state:\t%u [ 0 (TRACER_INIT), 1 (TRACER_RUNNING), "
		     "2 (TRACER_STOP) ]\n\n", sk_trace_params->tracer_state);

		for (i = 0; i < array->count; i++) {
			if (array->offsets[i].ready != 1)
				offset_dump(i, &array->offsets[i]);
		}

		printf("CPUs: %d\n", array->count);

		offset_dump(i - 1, &array->offsets[i - 1]);

		mfbpf_sockopt_msg_free(sk_trace_params);
		return ETR_OK;
	default:
		return ETR_NOTSUPP;
	}
}

static int tracer_do_cmd(struct mfbpf_obj *obj, mfbpf_cmd_t cmd,
			 struct mfbpf_conf *conf)
{
	struct bpf_tracer_param_array *array;
	size_t size, i;
	int err;

	switch (conf->cmd) {
	case MFBPF_CMD_SHOW:
		err =
		    mfbpf_getsockopt(SOCKOPT_GET_TRACER_SHOW, NULL,
				     0, (void **)&array, &size);
		if (err != 0)
			return err;

		if (size < sizeof(*array)
		    || size != sizeof(*array) +
		    array->count * sizeof(struct bpf_tracer_param)) {
			fprintf(stderr, "corrupted response.\n");
			mfbpf_sockopt_msg_free(array);
			return ETR_INVAL;
		}

		for (i = 0; i < array->count; i++)
			tracer_dump(&array->tracers[i]);

		mfbpf_sockopt_msg_free(array);
		return ETR_OK;
	default:
		return ETR_NOTSUPP;
	}
}

struct mfbpf_obj tr_obj = {
	.name = "tracer",
	.help = tracer_help,
	.do_cmd = tracer_do_cmd,
};

struct mfbpf_obj socktrace_obj = {
	.name = "socktrace",
	.help = socktrace_help,
	.do_cmd = socktrace_do_cmd,
};

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"    " MFBPF_NAME " [OPTIONS] OBJECT { COMMAND | help }\n"
		"Parameters:\n"
		"    OBJECT  := { tracer socktrace }\n"
		"    COMMAND := { show list }\n"
		"Options:\n"
		"    -v, --verbose\n"
		"    -h, --help\n" "    -V, --version\n" "    -C, --color\n");
}

static struct mfbpf_obj *mfbpf_obj_get(const char *name)
{
	if (strcmp(name, "tracer") == 0) {
		return &tr_obj;
	} else if (strcmp(name, "socktrace") == 0) {
		return &socktrace_obj;
	}

	return NULL;
}

static int parse_args(int argc, char *argv[], struct mfbpf_conf *conf)
{
	int opt;
	struct mfbpf_obj *obj;
	struct option opts[] = {
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'V'},
		{"color", no_argument, NULL, 'C'},
		{NULL, 0, NULL, 0},
	};

	memset(conf, 0, sizeof(*conf));
	conf->af = AF_UNSPEC;

	if (argc <= 1) {
		usage();
		exit(0);
	}

	while ((opt = getopt_long(argc, argv, "vhVC", opts, NULL)) != -1) {
		switch (opt) {
		case 'v':
			conf->verbose = 1;
			break;
		case 'h':
			usage();
			exit(0);
		case 'V':
			printf(MFBPF_NAME "-" MFBPF_VERSION "\n");
			exit(0);
		case 'C':
			conf->color = true;
			break;
		case '?':
		default:
			fprintf(stderr, "Invalid option: %s\n", argv[optind]);
			return -1;
		}
	}

	/* at least two args for: obj and cmd */
	if (optind >= argc) {
		usage();
		exit(1);
	}

	argc -= optind;
	argv += optind;

	conf->obj = argv[0];
	if (argc < 2) {
		obj = mfbpf_obj_get(conf->obj);
		if (obj && obj->help)
			obj->help();
		else
			usage();
		exit(1);
	}

	if (strcmp(argv[1], "show") == 0 || strcmp(argv[1], "list") == 0) {
		conf->cmd = MFBPF_CMD_SHOW;
		goto show_exit;
	} else if (strcmp(argv[1], "help") == 0) {
		conf->cmd = MFBPF_CMD_HELP;
		goto show_exit;
	}
#if 0
	if (argc < 3) {
		usage();
		exit(1);
	}

	if (strcmp(argv[1], "set") == 0 && strcmp(argv[2], "delay"))
		conf->cmd = MFBPF_CMD_SETDELAY;
	else {
		usage();
		exit(1);
	}

	conf->argc = argc - 3;
	conf->argv = argv + 3;
	return 0;
#endif
show_exit:
	conf->argc = argc - 2;
	conf->argv = argv + 2;
	return 0;
}

int main(int argc, char *argv[])
{
	char *prog;
	struct mfbpf_conf conf;
	struct mfbpf_obj *obj;
	int err;

	if ((prog = strchr(argv[0], '/')) != NULL)
		*prog++ = '\0';
	else
		prog = argv[0];

	if (parse_args(argc, argv, &conf) != 0)
		exit(1);

	if ((obj = mfbpf_obj_get(conf.obj)) == NULL) {
		fprintf(stderr, "%s: invalid object, use `-h' for help.\n",
			prog);
		exit(1);
	}

	if (conf.cmd == MFBPF_CMD_HELP) {
		if (obj->help) {
			obj->help();
			return ETR_OK;
		}
	}

	if ((err = obj->do_cmd(obj, conf.cmd, &conf)) != ETR_OK) {
		fprintf(stderr, "%s: %s\n", prog, trace_strerror(err));
		exit(1);
	}

	exit(0);
}
