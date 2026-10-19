#!/usr/bin/env python

import io
import os


ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(ROOT)))


def read_source(root, path):
    with io.open(os.path.join(root, path), encoding="utf-8") as source:
        return source.read()


KERNEL = read_source(ROOT, "kernel/socket_trace.bpf.c")
CONFIG_H = read_source(ROOT, "user/config.h")
SOCKET_USER = read_source(ROOT, "user/socket.c")
SOCKET_USER_H = read_source(ROOT, "user/socket.h")
RUST_CONFIG = read_source(REPO, "agent/src/config/config.rs")
RUST_HANDLER = read_source(REPO, "agent/src/config/handler.rs")
RUST_DISPATCHER = read_source(REPO, "agent/src/ebpf_dispatcher.rs")
TEMPLATE = read_source(REPO, "server/agent_config/template.yaml")


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def block(source, begin, end):
    start = source.find(begin)
    require(start != -1, "missing {}".format(begin))
    finish = source.find(end, start)
    require(finish != -1, "missing end marker {}".format(end))
    return source[start:finish]


require(
    "BPF_MAP_TYPE_LRU_HASH" in KERNEL and "__udp_peer_map" in KERNEL,
    "UDP peer state must use an LRU hash map",
)
require(
    "#define LOOP_LIMIT 18" in KERNEL
    and "#define EXTRA_LOOP_LIMIT 1" in KERNEL
    and "len, EXTRA_LOOP_LIMIT" in KERNEL,
    "the main iovec path must retain 18 entries while the extra DNS path uses one",
)
require(
    "MAP_ARRAY(udp_peer_id_enabled_map, __u32, __u32, 1" in KERNEL,
    "UDP peer isolation must use a single-entry runtime switch",
)

rewrite = block(
    KERNEL,
    "rewrite_udp_peer_metadata(",
    "static __inline int finalize_data_output",
)
key_builder = block(
    KERNEL,
    "build_udp_peer_key(",
    "rewrite_udp_peer_metadata(",
)
require(
    rewrite.find("event->tuple.l4_protocol != IPPROTO_UDP")
    < rewrite.find("udp_peer_id_enabled_map__lookup"),
    "non-UDP events must return before looking up the feature switch",
)
require(
    "event->socket_id == 0" in rewrite
    and "event->tuple.num == 0" in key_builder
    and "event->tuple.dport == 0" in key_builder
    and "udp_peer_addr_is_zero(key->local_addr" in key_builder
    and "udp_peer_addr_is_zero(key->remote_addr" in key_builder,
    "incomplete UDP tuples must retain physical metadata",
)
require(
    "BPF_NOEXIST" in rewrite
    and rewrite.count("udp_peer_map__lookup(key)") >= 2,
    "peer creation must use BPF_NOEXIST and re-lookup the winning state",
)
require(
    rewrite.find("if (!state)\n\t\t\treturn 0;")
    < rewrite.find("event->socket_id = peer_socket_id"),
    "event metadata must not be partially rewritten before state recovery",
)
require(
    "static_always_inline __u64\nrewrite_udp_peer_metadata" in KERNEL,
    "the main rewrite helper must return a scalar instead of a map-value pointer",
)

extra = block(
    KERNEL,
    "output_extra_data_common(",
    "#if defined(LINUX_VER_KFUNC) || defined(LINUX_VER_5_2_PLUS)",
)
require(
    "struct udp_peer_key_t *peer_key" in extra
    and "__u64 peer_socket_id" in extra,
    "sendmmsg extra output must receive the stack key and scalar peer socket ID",
)
require(
    extra.find("if (copy_bytes < 0)") < extra.find("if (peer_socket_id)"),
    "sendmmsg must allocate the extra peer sequence only after copy succeeds",
)
require(
    "udp_peer_map__lookup(peer_key)" in extra
    and "state->socket_id != peer_socket_id" in extra
    and "__sync_fetch_and_add(&state->seq, 1)" in extra,
    "sendmmsg extra output must re-lookup and validate the shared peer state",
)
require(
    extra.find("output_iov_data_copy")
    < extra.find("udp_peer_map__lookup(peer_key)"),
    "the extra peer state must be looked up only after payload copy succeeds",
)

output_region = KERNEL[KERNEL.find("static_always_inline int output_extra_data_common") :]
direct_output = block(
    output_region,
    "static __inline int __output_data_common(",
    "This eBPF program is specially used to transmit data",
)
require(
    "rewrite_udp_peer_metadata" not in direct_output
    and "v_buff, v, NULL, 0" in direct_output,
    "the direct close/IO path must not pull peer map logic into large syscall programs",
)

output = block(
    output_region,
    "static __inline int output_data_common(void *ctx)",
    "PROGTP(output_data)",
)
require(
    "rewrite_udp_peer_metadata(v, tracer_ctx, &peer_key)" in output
    and "struct udp_peer_key_t peer_key" in output
    and "v, &peer_key, peer_socket_id" in output,
    "the normal output program must pass its stack key and scalar peer identity to extra output",
)

require(
    'MAP_UDP_PEER_NAME               "__udp_peer_map"' in CONFIG_H
    and 'MAP_UDP_PEER_ENABLED_NAME       "__udp_peer_id_enabled_map"' in CONFIG_H,
    "userspace map names must match the BPF symbols",
)
require(
    "void set_udp_peer_id_enabled(bool enabled)" in SOCKET_USER_H
    and "void set_udp_peer_id_enabled(bool enabled)" in SOCKET_USER,
    "socket tracer must expose the UDP peer isolation switch",
)
require(
    "!udp_peer_id_enabled" in SOCKET_USER
    and "MAP_UDP_PEER_NAME, 1" in SOCKET_USER,
    "disabled UDP peer isolation must shrink the LRU map to one entry",
)
require(
    "MAP_UDP_PEER_ENABLED_NAME" in SOCKET_USER
    and "udp_peer_id_enabled_value" in SOCKET_USER,
    "userspace must initialize the UDP peer runtime switch before attach",
)

require(
    "pub udp_peer_id_enabled: bool" in RUST_CONFIG
    and "udp_peer_id_enabled: false" in RUST_CONFIG,
    "agent configuration must default UDP peer isolation to false",
)
require(
    '"inputs.ebpf.socket.tunning.udp_peer_id_enabled"' in RUST_HANDLER,
    "UDP peer isolation changes must request an agent restart",
)
peer_startup = block(
    RUST_DISPATCHER,
    "let udp_peer_id_enabled =",
    "ebpf::set_udp_peer_id_enabled(udp_peer_id_enabled);",
)
require(
    "if udp_peer_id_enabled {" in peer_startup
    and "info!(" in peer_startup
    and "warn!(" not in peer_startup
    and "wildcard UDP sockets may fall back to physical socket IDs" in peer_startup,
    "enabling UDP peer isolation must log missing wildcard local IPs at info level on v6.6",
)
require(
    "udp_peer_id_enabled: false" in TEMPLATE,
    "the generated agent configuration must expose the disabled-by-default switch",
)

print("[OK] UDP peer socket ID contracts")
