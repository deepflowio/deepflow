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

#include "ctrl.h"
#include "log.h"

char ipc_unix_domain[256];
static int srv_fd;
static struct list_head sockopt_list;

static inline int judge_id_betw(sockoptid_t num, sockoptid_t min,
				sockoptid_t max)
{
	return ((num <= max) && (num >= min));
}

static inline int sockopts_exist(struct tracer_sockopts *sockopts)
{
	struct tracer_sockopts *skopt;
	if (unlikely(NULL == sockopts))
		return 0;

	list_for_each_entry(skopt, &sockopt_list, list) {
		if (judge_id_betw
		    (sockopts->set_opt_min, skopt->set_opt_min,
		     skopt->set_opt_max)
		    || judge_id_betw(sockopts->set_opt_max, skopt->set_opt_min,
				     skopt->set_opt_max)) {
			return 1;
		}
		if (judge_id_betw
		    (sockopts->get_opt_min, skopt->get_opt_min,
		     skopt->get_opt_max)
		    || judge_id_betw(sockopts->get_opt_max, skopt->get_opt_min,
				     skopt->get_opt_max)) {
			return 1;
		}
	}
	return 0;
}

int sockopt_register(struct tracer_sockopts *sockopts)
{
	if (unlikely(NULL == sockopts)) {
		ebpf_info("%s: invalid socket msg type\n", __func__);
		return ETR_INVAL;
	}

	if (sockopts_exist(sockopts)) {
		ebpf_info("%s: socket msg type already exist\n", __func__);
		ebpf_info("sockopt type already exist "
			  "get: %d - %d set: %d - %d\n",
			  sockopts->get_opt_min, sockopts->get_opt_max,
			  sockopts->set_opt_min, sockopts->set_opt_max);

		return ETR_EXIST;
	}

	ebpf_info("sockopt register succeed, type "
		  "get: %d - %d set: %d - %d\n",
		  sockopts->get_opt_min, sockopts->get_opt_max,
		  sockopts->set_opt_min, sockopts->set_opt_max);

	list_add_tail(&sockopts->list, &sockopt_list);

	return ETR_OK;
}

int sockopt_unregister(struct tracer_sockopts *sockopts)
{
	struct tracer_sockopts *skopt, *next;

	if (unlikely(NULL == sockopts)) {
		ebpf_info("%s: invalid socket msg type\n", __func__);
		return ETR_INVAL;
	}
	list_for_each_entry_safe(skopt, next, &sockopt_list, list) {
		if (sockopts == skopt) {
			list_del_init(&skopt->list);
			return ETR_OK;
		}
	}
	return ETR_NOTEXIST;
}

static inline int sockopt_init(void)
{
	struct sockaddr_un srv_addr;
	//int srv_fd_flags = 0;

	memset(ipc_unix_domain, 0, sizeof(ipc_unix_domain));
	strncpy(ipc_unix_domain, UNIX_DOMAIN_DEF, sizeof(ipc_unix_domain) - 1);

	srv_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (srv_fd < 0) {
		ebpf_info("[%s] Fail to create server socket\n", __func__);
		return ETR_IO;
	}

	memset(&srv_addr, 0, sizeof(struct sockaddr_un));
	srv_addr.sun_family = AF_UNIX;

	ipc_unix_domain[sizeof(srv_addr.sun_path) - 1] = '\0'; // avoid strncpy(), which generates warnings
	strcpy(srv_addr.sun_path, ipc_unix_domain);

	unlink(ipc_unix_domain);

	if (-1 == bind(srv_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr))) {
		ebpf_info("[%s] Fail to bind server socket\n", __func__);
		close(srv_fd);
		unlink(ipc_unix_domain);
		return ETR_IO;
	}

	if (-1 == listen(srv_fd, 1)) {
		ebpf_info("[%s] Server socket listen failed\n", __func__);
		close(srv_fd);
		unlink(ipc_unix_domain);
		return ETR_IO;
	}

	return ETR_OK;
}

int ctrl_init(void)
{
	init_list_head(&sockopt_list);
	int ret = sockopt_init();
	if (unlikely(ret < 0)) {
		ebpf_info("[%s] sockopt module initialization failed!\n",
			  __func__);
		return ret;
	}
	return ETR_OK;
}

ssize_t sendn(int fd, const void *vptr, size_t n, int flags)
{
	size_t nleft;
	ssize_t nwritten;
	const char *ptr;

	ptr = vptr;
	nleft = n;

	while (nleft > 0) {
		if ((nwritten = send(fd, ptr, nleft, flags)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;	/* and call send() again */
			else
				return (-1);	/* error */
		}

		nleft -= nwritten;
		ptr += nwritten;
	}

	return (n);
}

ssize_t readn(int fd, void *vptr, size_t n)
{
	size_t nleft;
	ssize_t nread;
	char *ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ((nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;	/* and call read() again */
			else
				return (-1);
		} else if (nread == 0)
			break;	/* EOF */

		nleft -= nread;
		ptr += nread;
	}

	return (n - nleft);	/* return >= 0 */
}

static inline int sockopt_msg_recv(int clt_fd, struct tracer_sock_msg **pmsg)
{
	struct tracer_sock_msg msg_hdr;
	struct tracer_sock_msg *msg;
	int res;

	if (unlikely(!pmsg))
		return ETR_INVAL;
	*pmsg = NULL;

	memset(&msg_hdr, 0, sizeof(msg_hdr));
	res = read(clt_fd, &msg_hdr, sizeof(msg_hdr));
	if (sizeof(msg_hdr) != res) {
		ebpf_info("[%s] sockopt msg header recv fail: %s\n", __func__,
			  strerror(errno));
		return ETR_IO;
	}

	*pmsg = malloc(sizeof(struct tracer_sock_msg) + msg_hdr.len);
	if (unlikely(NULL == *pmsg)) {
		ebpf_warning("malloc() failed, no memory\n");
		return ETR_NOMEM;
	}

	msg = *pmsg;
	msg->version = msg_hdr.version;
	msg->id = msg_hdr.id;
	msg->type = msg_hdr.type;
	msg->len = msg_hdr.len;

	if (msg_hdr.len > 0) {
		res = read(clt_fd, msg->data, msg->len);
		if (res != msg->len) {
			ebpf_info("[%s] sockopt msg body recv fail: %s\n",
				  __func__, strerror(errno));
			free(msg);
			*pmsg = NULL;
			return ETR_IO;
		}
	}

	return ETR_OK;
}

static struct tracer_sockopts *sockopts_get(struct tracer_sock_msg *msg)
{
	struct tracer_sockopts *skopt;
	if (unlikely(NULL == msg))
		return NULL;

	switch (msg->type) {
	case SOCKOPT_GET:
		list_for_each_entry(skopt, &sockopt_list, list) {
			if (judge_id_betw
			    (msg->id, skopt->get_opt_min, skopt->get_opt_max)) {
				if (unlikely(skopt->version != msg->version)) {
					ebpf_info
					    ("%s: socket msg version not match\n",
					     __func__);
					return NULL;
				}
				return skopt;
			}
		}
		return NULL;
		break;
	case SOCKOPT_SET:
		list_for_each_entry(skopt, &sockopt_list, list) {
			if (judge_id_betw
			    (msg->id, skopt->set_opt_min, skopt->set_opt_max)) {
				if (unlikely(skopt->version != msg->version)) {
					ebpf_info
					    ("%s: socket msg version not match\n",
					     __func__);
					return NULL;
				}
				return skopt;
			}
		}
		return NULL;
		break;
	default:
		ebpf_info("%s: unkown sock msg type: %d\n", __func__,
			  msg->type);
	}
	return NULL;
}

/* Note:
 * 1. data is created by user using malloc, zmalloc, etc.
 * 2. msg data not sent when errcode is set in reply header */
static int sockopt_msg_send(int clt_fd,
			    const struct tracer_sock_msg_reply *hdr,
			    const char *data, int data_len)
{
	int len, res;

	len = sizeof(struct tracer_sock_msg_reply);
	res = sendn(clt_fd, hdr, len, MSG_NOSIGNAL);
	if (len != res) {
		ebpf_info("[%s:msg#%d] sockopt reply msg header send error"
			  " -- %d/%d sent\n", __func__, hdr->id, res, len);
		return ETR_IO;
	}

	if (hdr->errcode) {
		ebpf_info("[%s:msg#%d] errcode set in sockopt msg reply: %s\n",
			  __func__, hdr->id, trace_strerror(hdr->errcode));
		return hdr->errcode;
	}

	if (data_len) {
		res = sendn(clt_fd, data, data_len, MSG_NOSIGNAL);
		if (data_len != res) {
			ebpf_info
			    ("[%s:msg#%d] sockopt reply msg body send error"
			     " -- %d/%d sent\n", __func__, hdr->id, res,
			     data_len);
			return ETR_IO;
		}
	}

	return ETR_OK;
}

/* free recieved msg */
static inline void sockopt_msg_free(struct tracer_sock_msg *msg)
{
	free(msg);
}

int sockopt_ctl(__unused void *arg)
{
	int clt_fd;
	int ret;
	socklen_t clt_len;
	struct sockaddr_un clt_addr;
	struct tracer_sockopts *skopt;
	struct tracer_sock_msg *msg;
	struct tracer_sock_msg_reply reply_hdr;
	void *reply_data = NULL;
	size_t reply_data_len = 0;

	memset(&clt_addr, 0, sizeof(struct sockaddr_un));
	clt_len = sizeof(clt_addr);

	if (srv_fd == 0)
		return ETR_IO;

	/* Note: srv_fd is nonblock */
	clt_fd = accept(srv_fd, (struct sockaddr *)&clt_addr, &clt_len);
	if (clt_fd < 0) {
		if (EWOULDBLOCK != errno) {
			ebpf_info("[%s] Fail to accept client request\n",
				  __func__);
			close(srv_fd);
			srv_fd = 0;
			/*unlink(ipc_unix_domain); */
		}
		return ETR_IO;
	}

	/* Note: clt_fd is block */
	ret = sockopt_msg_recv(clt_fd, &msg);
	if (unlikely(ETR_OK != ret)) {
		close(clt_fd);
		/*unlink(ipc_unix_domain); */
		return ret;
	}

	skopt = sockopts_get(msg);
	if (skopt) {
		if (msg->type == SOCKOPT_GET)
			ret =
			    skopt->get(msg->id, msg->data, msg->len,
				       &reply_data, &reply_data_len);
		else if (msg->type == SOCKOPT_SET)
			ret = skopt->set(msg->id, msg->data, msg->len);
		if (ret < 0) {
			/* assume that reply_data is freed by user when callback fails */
			reply_data = NULL;
			reply_data_len = 0;
			ebpf_info
			    ("[%s] socket msg<type=%s, id=%d> callback failed\n",
			     __func__, msg->type == SOCKOPT_GET ? "GET" : "SET",
			     msg->id);
		}

		memset(&reply_hdr, 0, sizeof(reply_hdr));
		reply_hdr.version = SOCKOPT_VERSION;
		reply_hdr.id = msg->id;
		reply_hdr.type = msg->type;
		reply_hdr.errcode = ret;
		strncpy(reply_hdr.errstr, trace_strerror(ret),
			SOCKOPT_ERRSTR_LEN - 1);
		reply_hdr.len = reply_data_len;

		/* send response */
		ret =
		    sockopt_msg_send(clt_fd, &reply_hdr, reply_data,
				     reply_data_len);

		if (reply_data)
			free(reply_data);

		if (ETR_OK != ret) {
			sockopt_msg_free(msg);
			close(clt_fd);
			return ret;
		}
	}

	sockopt_msg_free(msg);
	close(clt_fd);

	return ETR_OK;
}
