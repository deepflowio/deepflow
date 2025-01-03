/*  XDP redirect to CPUs via cpumap (BPF_MAP_TYPE_CPUMAP)
 *
 *  GPLv2, Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */

/*
 * Linux 4.14: Added support for BPF_MAP_TYPE_CPUMAP, allowing packets to be
 * redirected to specific CPUs.
 */

#include <sys/socket.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "../../config.h"
#include "bpf_base.h"
#include "common.h"
#include "kernel.h"
#include "bpf_endian.h"
#include "cpumap_config.h"
#include "../../../types.h"
#include <bcc/compat/linux/bpf.h>
#include "byteorder/generic.h"
#include "gre.h"
#include "bild_erspan.h"
#include "hash_func01.h"

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)                      \
({                                                \
  char ____fmt[] = fmt;                           \
  bpf_trace_printk(____fmt, sizeof(____fmt),      \
       ##__VA_ARGS__);                \
})

#define CALC_MOD(a, b)  \
    ( (((b) & ((b)-1)) == 0) ? \
((a) & ((b)-1)) : ((a) - (a) / (__u32)(b) * (__u32)(b)) )

#define IP_ADDR_TO_U8(ip_addr_int) ( \
    ( (__u8*)(&(ip_addr_int)) )[0] ^ \
    ( (__u8*)(&(ip_addr_int)) )[1] ^ \
    ( (__u8*)(&(ip_addr_int)) )[2] ^ \
    ( (__u8*)(&(ip_addr_int)) )[3] )

#define PORT_TO_U8(port) ( \
    ( (__u8*)(&(port)) )[0] ^ \
    ( (__u8*)(&(port)) )[1] )

#define IP_PKT_HASH(iph) \
    ( ((iph)->protocol ^ \
 IP_ADDR_TO_U8((iph)->saddr) ^ \
 IP_ADDR_TO_U8((iph)->daddr)) )

#define TCP_PKT_HASH(tcp) \
    ( PORT_TO_U8((tcp)->source) ^ \
PORT_TO_U8((tcp)->dest) )

#define UDP_PKT_HASH(udp) \
    ( PORT_TO_U8((udp)->source) ^ \
PORT_TO_U8((udp)->dest) )

#define IPV6_ADDR_TO_U8(ipv6_addr) ( \
  ipv6_addr.in6_u.u6_addr8[0] ^ \
  ipv6_addr.in6_u.u6_addr8[1] ^ \
  ipv6_addr.in6_u.u6_addr8[2] ^ \
  ipv6_addr.in6_u.u6_addr8[3] ^ \
  ipv6_addr.in6_u.u6_addr8[4] ^ \
  ipv6_addr.in6_u.u6_addr8[5] ^ \
  ipv6_addr.in6_u.u6_addr8[6] ^ \
  ipv6_addr.in6_u.u6_addr8[7] ^ \
  ipv6_addr.in6_u.u6_addr8[8] ^ \
  ipv6_addr.in6_u.u6_addr8[9] ^ \
  ipv6_addr.in6_u.u6_addr8[10] ^ \
  ipv6_addr.in6_u.u6_addr8[11] ^ \
  ipv6_addr.in6_u.u6_addr8[12] ^ \
  ipv6_addr.in6_u.u6_addr8[13] ^ \
  ipv6_addr.in6_u.u6_addr8[14] ^ \
  ipv6_addr.in6_u.u6_addr8[15] )

#define IPV6_PKT_HASH(ip6h) \
    ( ((ip6h)->nexthdr ^ \
 IPV6_ADDR_TO_U8((ip6h)->saddr) ^ \
 IPV6_ADDR_TO_U8((ip6h)->daddr)) )

/* Common stats data record to keep userspace more simple */
struct datarec {
	__u64 processed;
	__u64 dropped;
	__u64 issue;
	__u32 ifindex;
	__u32 to_cpu;
};

/* *INDENT-OFF* */
/* Special map type that can XDP_REDIRECT frames to another CPU */
struct bpf_map_def SEC("maps") cpu_map =
{
	.type = BPF_MAP_TYPE_CPUMAP,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = MAX_CPU,
	.feat_flags = FEATURE_CPU_BALANCER, 
};

/* Count RX packets, as XDP bpf_prog doesn't get direct TX-success
 * feedback.  Redirect TX errors can be caught via a tracepoint.
 */
struct bpf_map_def SEC("maps") rx_cnt =
{
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct datarec),
	.max_entries = 1,
	.feat_flags = FEATURE_CPU_BALANCER,
};

/* Used by trace point */
struct bpf_map_def SEC("maps") redirect_err_cnt =
{
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct datarec),
	.max_entries = 2,
	.feat_flags = FEATURE_CPU_BALANCER,
	/* TODO: have entries for all possible errno's */
};

/* Used by trace point */
struct bpf_map_def SEC("maps") cpumap_enqueue_cnt =
{
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct datarec),
	.max_entries = MAX_CPU,
	.feat_flags = FEATURE_CPU_BALANCER,
};

/* Used by trace point */
struct bpf_map_def SEC("maps") cpumap_kthread_cnt =
{
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct datarec),
	.max_entries = 1,
	.feat_flags = FEATURE_CPU_BALANCER,
};

/* Set of maps controlling available CPU, and for iterating through
 * selectable redirect CPUs.
 */
struct bpf_map_def SEC("maps") cpus_available =
{
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = MAX_CPU,
	.feat_flags = FEATURE_CPU_BALANCER,
};

struct bpf_map_def SEC("maps") cpus_count =
{
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 1,
	.feat_flags = FEATURE_CPU_BALANCER,
};

struct bpf_map_def SEC("maps") cpus_iterator =
{
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 1,
	.feat_flags = FEATURE_CPU_BALANCER,
};

struct bpf_map_def SEC("maps") exception_cnt =
{
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct datarec),
	.max_entries = 1,
	.feat_flags = FEATURE_CPU_BALANCER,
};

struct bpf_map_def SEC("maps") cpumap_pause =
{
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
	.feat_flags = FEATURE_CPU_BALANCER,
};

/* *INDENT-ON* */

/* Helper parse functions */

/* Parse Ethernet layer 2, extract network layer 3 offset and protocol
 *
 * Returns false on error and non-supported ether-type
 */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline
    bool parse_eth(struct ethhdr *eth, void *data_end,
		   u16 * eth_proto, u64 * l3_offset)
{
	u16 eth_type;
	u64 offset;

	offset = sizeof(*eth);
	if ((void *)eth + offset > data_end)
		return false;

	eth_type = eth->h_proto;

	/* Skip non 802.3 Ethertypes */
	if (unlikely(ntohs(eth_type) < ETH_P_802_3_MIN))
		return false;

	/* Handle VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
	/* Handle double VLAN tagged packet */
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)eth + offset > data_end)
			return false;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = ntohs(eth_type);
	*l3_offset = offset;
	return true;
}

static __always_inline __attribute__ ((__unused__)) u16
get_dest_port_ipv4_udp(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	struct udphdr *udph;
	u16 dport;

	if ((void *)(iph + 1) > data_end)
		return 0;
	if (!(iph->protocol == IPPROTO_UDP))
		return 0;

	udph = (void *)(iph + 1);
	if ((void *)(udph + 1) > data_end)
		return 0;

	dport = ntohs(udph->dest);
	return dport;
}

static __always_inline __attribute__ ((__unused__)) int
get_proto_ipv4(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;

	if ((void *)(iph + 1) > data_end)
		return 0;
	return iph->protocol;
}

static __always_inline __attribute__ ((__unused__)) int
get_proto_ipv6(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h = data + nh_off;

	if ((void *)(ip6h + 1) > data_end)
		return 0;
	return ip6h->nexthdr;
}

static __always_inline u8 get_ipv4_hash_ip_pair(struct xdp_md *ctx, u64 nh_off,
						u8 * l4pro, u64 * l4off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph = data + nh_off;
	u8 cpu_hash;

	if ((void *)(iph + 1) > data_end)
		return 0;

	cpu_hash = IP_PKT_HASH(iph);
	*l4pro = iph->protocol;

	*l4off = nh_off + (iph->ihl << 2);

	return cpu_hash;
}

static __always_inline u8 get_ipv6_hash_ip_pair(struct xdp_md *ctx, u64 nh_off,
						u8 * l4pro, u64 * l4off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h = data + nh_off;
	u8 cpu_hash;

	if ((void *)(ip6h + 1) > data_end)
		return 0;

	cpu_hash = IPV6_PKT_HASH(ip6h);
	*l4pro = ip6h->nexthdr;

	*l4off = nh_off + sizeof(struct ipv6hdr);

	return cpu_hash;
}

static __always_inline u8 get_hash_tcp_pair(struct xdp_md *ctx, u64 nh_off,
					    u8 hash_base)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct tcphdr *tcp = data + nh_off;
	u8 hash = hash_base;

	if ((void *)(tcp + 1) > data_end)
		return 0;

	hash ^= TCP_PKT_HASH(tcp);
	return hash;
}

static __always_inline u8 get_hash_udp_pair(struct xdp_md *ctx, u64 nh_off,
					    u8 hash_base)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct tcphdr *udp = data + nh_off;
	u8 hash = hash_base;

	if ((void *)(udp + 1) > data_end)
		return 0;

	hash ^= UDP_PKT_HASH(udp);
	return hash;
}

static __always_inline u8 gre_tunnel_process(struct xdp_md *ctx,
					     u64 nh_off,
					     u16 proto)
{
	//void *data_end = (void *)(long)ctx->data_end;
	//void *data = (void *)(long)ctx->data;
	u8 cpu_hash = 0;
	u64 l3_offset = 0, l4_offset = 0;
	u8 l4_proto = 0;
	l3_offset = nh_off;

	/* Hash for IPv4 and IPv6 */
	switch (proto) {
	case htons(ETH_P_IP):
		cpu_hash =
		    get_ipv4_hash_ip_pair(ctx, l3_offset, &l4_proto,
					  &l4_offset);
		break;
	case htons(ETH_P_IPV6):
		cpu_hash =
		    get_ipv6_hash_ip_pair(ctx, l3_offset, &l4_proto,
					  &l4_offset);
		break;
	default:
		cpu_hash = 0;
	}

	switch (l4_proto) {
	case IPPROTO_TCP:
		cpu_hash = get_hash_tcp_pair(ctx, l4_offset, cpu_hash);
		break;
	case IPPROTO_UDP:
		cpu_hash = get_hash_udp_pair(ctx, l4_offset, cpu_hash);
		break;
	default:
		break;
	}

	return cpu_hash;
}

static __always_inline u8 erspan_tunnel_process(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u8 cpu_hash = 0;
	int offset = nh_off;
	u16 eth_proto = 0;
	u64 l3_offset = 0, l4_offset = 0;
	u8 l4_proto = 0;

	struct ethhdr *eth = data + offset;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset)))
		return XDP_PASS;	/* Just skip */

	l3_offset += offset;

	/* Hash for IPv4 and IPv6 */
	switch (eth_proto) {
	case ETH_P_IP:
		cpu_hash =
		    get_ipv4_hash_ip_pair(ctx, l3_offset, &l4_proto,
					  &l4_offset);
		break;
	case ETH_P_IPV6:
		cpu_hash =
		    get_ipv6_hash_ip_pair(ctx, l3_offset, &l4_proto,
					  &l4_offset);
		break;
	case ETH_P_ARP:	/* ARP packet handled on CPU idx 0 */
	default:
		cpu_hash = 0;
	}

	switch (l4_proto) {
	case IPPROTO_TCP:
		cpu_hash = get_hash_tcp_pair(ctx, l4_offset, cpu_hash);
		break;
	case IPPROTO_UDP:
		cpu_hash = get_hash_udp_pair(ctx, l4_offset, cpu_hash);
		break;
	default:
		break;
	}

	return cpu_hash;
}

static __always_inline u8 get_hash_gre_pair(struct xdp_md *ctx, u64 nh_off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct gre_base_hdr *greh = data + nh_off;
	u8 hash = 0;
	int offset = nh_off;

	if ((void *)(greh + 1) > data_end)
		return 0;

	u16 proto = greh->protocol;
	u16 gflags = greh->flags;
	int hdr_len = gre_calc_hlen(gre_flags_to_tnl_flags(gflags));

	if (proto == htons(ETH_P_IP) || proto == htons(ETH_P_IPV6)) {
		offset += hdr_len;
		hash = gre_tunnel_process(ctx, offset, proto);
	} else if (proto == htons(ETH_P_ERSPAN)) {
		/*
		 * ERSPAN - Type I
		 */
		if (gflags == 0) {
			offset += sizeof(struct gre_base_hdr);
			hash = erspan_tunnel_process(ctx, offset);
		} else if (gflags & GRE_SEQ) {
			/*
			 * ERSPAN - Type II
			 */
			struct erspan_type2_full_hdr {
				struct gre_base_hdr gre_base;
				__be32 seq;
				struct erspan_base_hdr erspan_hdr;
				__u32 erspan_v1_md;
			};
			offset += sizeof(struct erspan_type2_full_hdr);
			hash = erspan_tunnel_process(ctx, offset);
		}

	} else if (proto == htons(ETH_P_ERSPAN2)) {
#define ERSPAN_V2_MDSIZE        8
		/*
		 * ERSPAN - Type III
		 */
		hdr_len += (sizeof(struct erspan_base_hdr) + ERSPAN_V2_MDSIZE);
		offset += hdr_len;
		hash = erspan_tunnel_process(ctx, offset);
	}

	return hash;
}

/* Load-Balance traffic based on hashing IP-addrs + L4-proto.  The
 * hashing scheme is symmetric, meaning swapping IP src/dest still hit
 * same CPU.
 */
SEC("xdp_cpu_map_lb_hash")
int xdp_prog_lb_hash(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct datarec *rec;
	u16 eth_proto = 0;
	u64 l3_offset = 0, l4_offset = 0;
	u32 cpu_dest = 0;
	u32 cpu_idx = 0;
	u32 *cpu_lookup;
	u32 *cpu_max;
	u8 cpu_hash;
	u32 key = 0, key0 = 0;
	u8 l4_proto = 0;

	unsigned int *cpumap_pause_value;
	cpumap_pause_value = bpf_map_lookup_elem(&cpumap_pause, &key0);
	if (unlikely(!cpumap_pause_value)) {
		bpf_printk("bpf_map_lookup_elem debug_flag error.\n");
		return XDP_PASS;
	}

	if (unlikely(*cpumap_pause_value == 1)) {
		return XDP_PASS;
	}

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;
	rec->processed++;
	rec->ifindex = ctx->ingress_ifindex;

	cpu_max = bpf_map_lookup_elem(&cpus_count, &key);
	if (!cpu_max)
		return XDP_PASS;

	if (!(parse_eth(eth, data_end, &eth_proto, &l3_offset)))
		return XDP_PASS;	/* Just skip */

	/* Hash for IPv4 and IPv6 */
	switch (eth_proto) {
	case ETH_P_IP:
		cpu_hash =
		    get_ipv4_hash_ip_pair(ctx, l3_offset, &l4_proto,
					  &l4_offset);
		break;
	case ETH_P_IPV6:
		cpu_hash =
		    get_ipv6_hash_ip_pair(ctx, l3_offset, &l4_proto,
					  &l4_offset);
		break;
	case ETH_P_ARP:	/* ARP packet handled on CPU idx 0 */
	default:
		cpu_hash = 0;
	}

	switch (l4_proto) {
	case IPPROTO_TCP:
		cpu_hash = get_hash_tcp_pair(ctx, l4_offset, cpu_hash);
		break;
	case IPPROTO_GRE:
		cpu_hash = get_hash_gre_pair(ctx, l4_offset);
		break;
	case IPPROTO_UDP:
		cpu_hash = get_hash_udp_pair(ctx, l4_offset, cpu_hash);
		break;
	default:
		break;
	}

	cpu_hash ^= cpu_hash >> 4;
	cpu_hash ^= cpu_hash >> 2;

	/* Choose CPU based on hash */
	cpu_idx = CALC_MOD(cpu_hash, *cpu_max);

	cpu_lookup = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
	if (!cpu_lookup)
		return XDP_PASS;
	cpu_dest = *cpu_lookup;

	if (cpu_dest >= MAX_CPU) {
		rec->issue++;
		return XDP_PASS;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

char _license[] SEC("license") = "GPL";

/*** Trace point code ***/

/* Tracepoint format: /sys/kernel/debug/tracing/events/xdp/xdp_redirect/format
 * Code in:                kernel/include/trace/events/xdp.h
 */
struct xdp_redirect_ctx {
	u64 __pad;		// First 8 bytes are not accessible by bpf code
	int prog_id;		//      offset:8;  size:4; signed:1;
	u32 act;		//      offset:12  size:4; signed:0;
	int ifindex;		//      offset:16  size:4; signed:1;
	int err;		//      offset:20  size:4; signed:1;
	int to_ifindex;		//      offset:24  size:4; signed:1;
	u32 map_id;		//      offset:28  size:4; signed:0;
	int map_index;		//      offset:32  size:4; signed:1;
};				//      offset:36

enum {
	XDP_REDIRECT_SUCCESS = 0,
	XDP_REDIRECT_ERROR = 1
};

static __always_inline
    int xdp_redirect_collect_stat(struct xdp_redirect_ctx *ctx)
{
	u32 key = XDP_REDIRECT_ERROR;
	struct datarec *rec;
	int err = ctx->err;

	if (!err)
		key = XDP_REDIRECT_SUCCESS;

	rec = bpf_map_lookup_elem(&redirect_err_cnt, &key);
	if (!rec)
		return 0;
	rec->dropped += 1;
	rec->ifindex = ctx->ifindex;
	return 0;		/* Indicate event was filtered (no further processing) */
	/*
	 * Returning 1 here would allow e.g. a perf-record tracepoint
	 * to see and record these events, but it doesn't work well
	 * in-practice as stopping perf-record also unload this
	 * bpf_prog.  Plus, there is additional overhead of doing so.
	 */
}

TP_XDP_PROG(redirect_err) (struct xdp_redirect_ctx *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

TP_XDP_PROG(redirect_map_err)(struct xdp_redirect_ctx *ctx)
{
	return xdp_redirect_collect_stat(ctx);
}

/* Tracepoint format: /sys/kernel/debug/tracing/events/xdp/xdp_exception/format
 * Code in:                kernel/include/trace/events/xdp.h
 */
struct xdp_exception_ctx {
	u64 __pad;		// First 8 bytes are not accessible by bpf code
	int prog_id;		//      offset:8;  size:4; signed:1;
	u32 act;		//      offset:12; size:4; signed:0;
	int ifindex;		//      offset:16; size:4; signed:1;
};

TP_XDP_PROG(exception) (struct xdp_exception_ctx *ctx)
{
	struct datarec *rec;
	u32 key = 0;

	rec = bpf_map_lookup_elem(&exception_cnt, &key);
	if (!rec)
		return 1;
	rec->dropped += 1;
	rec->ifindex = ctx->ifindex;

	return 0;
}

/* Tracepoint: /sys/kernel/debug/tracing/events/xdp/xdp_cpumap_enqueue/format
 * Code in:         kernel/include/trace/events/xdp.h
 */
struct cpumap_enqueue_ctx {
	u64 __pad;		// First 8 bytes are not accessible by bpf code
	int map_id;		//      offset:8;  size:4; signed:1;
	u32 act;		//      offset:12; size:4; signed:0;
	int cpu;		//      offset:16; size:4; signed:1;
	unsigned int drops;	//      offset:20; size:4; signed:0;
	unsigned int processed;	//      offset:24; size:4; signed:0;
	int to_cpu;		//      offset:28; size:4; signed:1;
};

TP_XDP_PROG(cpumap_enqueue) (struct cpumap_enqueue_ctx *ctx)
{
	u32 to_cpu = ctx->to_cpu;
	struct datarec *rec;

	if (to_cpu >= MAX_CPU)
		return 1;

	rec = bpf_map_lookup_elem(&cpumap_enqueue_cnt, &to_cpu);
	if (!rec)
		return 0;
	rec->processed += ctx->processed;
	rec->dropped += ctx->drops;
	rec->to_cpu = ctx->to_cpu;

	/* Record bulk events, then userspace can calc average bulk size */
	if (ctx->processed > 0)
		rec->issue += 1;

	/* Inception: It's possible to detect overload situations, via
	 * this tracepoint.  This can be used for creating a feedback
	 * loop to XDP, which can take appropriate actions to mitigate
	 * this overload situation.
	 */
	return 0;
}

/* Tracepoint: /sys/kernel/debug/tracing/events/xdp/xdp_cpumap_kthread/format
 * Code in:         kernel/include/trace/events/xdp.h
 */
struct cpumap_kthread_ctx {
	u64 __pad;		// First 8 bytes are not accessible by bpf code
	int map_id;		//      offset:8;  size:4; signed:1;
	u32 act;		//      offset:12; size:4; signed:0;
	int cpu;		//      offset:16; size:4; signed:1;
	unsigned int drops;	//      offset:20; size:4; signed:0;
	unsigned int processed;	//      offset:24; size:4; signed:0;
	int sched;		//      offset:28; size:4; signed:1;
};

TP_XDP_PROG(cpumap_kthread) (struct cpumap_kthread_ctx *ctx)
{
	struct datarec *rec;
	u32 key = 0;

	rec = bpf_map_lookup_elem(&cpumap_kthread_cnt, &key);
	if (!rec)
		return 0;
	rec->processed += ctx->processed;
	rec->dropped += ctx->drops;
	rec->to_cpu = ctx->cpu;

	/* Count times kthread yielded CPU via schedule call */
	if (ctx->sched)
		rec->issue++;

	return 0;
}
