/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2025- The Yunshan Networks Authors.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */


#include <sys/socket.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "include/bpf_base.h"
#include "config.h"
#include "include/common.h"
#include "include/kernel.h"
#include "include/bpf_endian.h"

struct trace_event_raw_sys_enter;
struct trace_event_raw_sys_exit;

char LICENSE[] SEC("license") = "GPL";

#define TCPHDR_SYN 0x02
#define TCPHDR_PSH 0x08
#define TCP_OPTION_TRACING_CODE 253
#define TCP_OPTION_TRACING_MAGIC 0xDEE9
#define TCP_OPTION_TRACING_FULL_LEN 12

struct __attribute__((packed)) tcp_option_tracing {
	__u8 opcode;
	__u8 opsize;
	__u16 magic;
	__u32 pid;
	__u32 saddr;
};

MAP_PERARRAY(percpu_syscall_proc_map, int, __u64, 1, 0);
MAP_ARRAY(tcp_option_trace_conf, __u32, __u32, 1, FEATURE_FLAG_SOCKET_TRACER);

static_always_inline __u32 get_sampling_window_bytes(void)
{
	__u32 key = 0;
	__u32 *value = tcp_option_trace_conf__lookup(&key);
	if (!value)
		return 0;
	return *value;
}

static_always_inline bool load_tcp_seq_network(const struct tcphdr *th,
				       __u32 *seq_network)
{
	if (bpf_probe_read_kernel(seq_network, sizeof(*seq_network), &th->seq)) {
		return false;
	}
	return true;
}

/*
|------------------------|-----------------------|-----------------------|   <-- TCP 序列号窗口，每个窗口大小为 window 字节
0                       4096                    8192                    12288

                [--------------------]                         <-- 当前数据包的序列号区间 [seq, seq+len)
                seq=3500             seq+len=4300 (跨过了4096)

                                   ^ 触发点：跨过了窗口末尾（4096），返回 true
*/
static bool is_cover_rounded_up_seq(struct bpf_sock_ops *skops)
{
	struct tcphdr *th = skops->skb_data;
	__u32 seq_network = 0;

	if (!load_tcp_seq_network(th, &seq_network)) {
		return false;
	}

	__u64 window = get_sampling_window_bytes();
	/* window == 0 means sampling is disabled, inject on every eligible skb */
	if (window == 0)
		return true;

	__u64 seq = __bpf_ntohl(seq_network);
	__u64 len = skops->skb_len;
	if (len == 0)
		return false;

	__u64 bucket_idx = seq / window;
	__u64 next_bucket_start = (bucket_idx + 1) * window;
	/* Inject when the payload reaches the last byte of the current window */
	return seq + len >= next_bucket_start;
}

static_always_inline __u64 sockops_current_pid_tgid()
{
	int zero = 0;
	__u64 *pid_tgid = percpu_syscall_proc_map__lookup(&zero);
	return pid_tgid ? *pid_tgid : 0;
}

static_always_inline int
syscall_pid_tgid_map_update(struct trace_event_raw_sys_enter *ctx)
{
	int key = 0;
	__u64 value = bpf_get_current_pid_tgid();

	percpu_syscall_proc_map__update(&key, &value);
	return 0;
}

static_always_inline int
syscall_pid_tgid_map_clear(struct trace_event_raw_sys_exit *ctx)
{
	int key = 0;
	__u64 value = 0;
	percpu_syscall_proc_map__update(&key, &value);
	return 0;
}

static_always_inline bool skops_can_add_option(struct bpf_sock_ops *skops)
{
	if (skops->skb_tcp_flags & TCPHDR_SYN) {
		return true;
	}

	if (!(skops->skb_tcp_flags & TCPHDR_PSH)) {
		return false;
	}

	if (!is_cover_rounded_up_seq(skops)) {
		return false;
	}

	return true;
}

static_always_inline void sockops_set_opt_len(struct bpf_sock_ops *skops, __u32 opt_len)
{
	struct sock *sk = (struct sock *)skops->sk;
	__u64 key;

	if (!sk)
		return;

	key = (__u64)(unsigned long)sk;
	if (!opt_len) {
		sock_opt_len_map__delete(&key);
		return;
	}

	sock_opt_len_map__update(&key, &opt_len);
}

static_always_inline __u32 sockops_get_opt_len(struct bpf_sock_ops *skops)
{
	struct sock *sk = (struct sock *)skops->sk;
	__u64 key;
	__u32 *opt_len;

	if (!sk)
		return 0;

	key = (__u64)(unsigned long)sk;
	opt_len = sock_opt_len_map__lookup(&key);
	return opt_len ? *opt_len : 0;
}

static_always_inline void
sockops_set_hdr_cb_flags(struct bpf_sock_ops *skops)
{
	bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
}

static_always_inline void sockops_tcp_reserve_hdr(struct bpf_sock_ops *skops)
{
	if (!skops_can_add_option(skops))
		return;

	// Let the bpf to determine if there is enough space for full option
	bpf_reserve_hdr_opt(skops, TCP_OPTION_TRACING_FULL_LEN, 0)
}

static_always_inline void sockops_tcp_store_hdr(struct bpf_sock_ops *skops)
{
	struct tcp_option_tracing tot;
	struct tcphdr *th = skops->skb_data;
	__u32 seq_network = 0;


	tot.opcode = TCP_OPTION_TRACING_CODE;
	tot.opsize = opt_len;
	tot.magic = __bpf_htons(TCP_OPTION_TRACING_MAGIC);
	tot.pid = __bpf_htonl(sockops_current_pid_tgid() >> 32);
	tot.addr = sockops->local_ip4;

	bpf_store_hdr_opt(skops, (void *)&tot, opt_len, 0);
}

SEC("sockops")
int sockops_write_tcp_options(struct bpf_sock_ops *skops)
{
	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		sockops_set_hdr_cb_flags(skops);
		break;
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		sockops_tcp_reserve_hdr(skops);
		break;
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		sockops_tcp_store_hdr(skops);
		break;
	}
	return 1;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	return syscall_pid_tgid_map_update(ctx);
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	return syscall_pid_tgid_map_clear(ctx);
}
