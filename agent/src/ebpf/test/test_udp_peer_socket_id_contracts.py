import os
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_udp_peer_cache_contracts import read_source


class UdpPeerIdContracts(unittest.TestCase):
    def test_mmsg_length_read_width(self):
        kernel = read_source("kernel/socket_trace.bpf.c")
        self.assertIn("unsigned int *msg_len;", read_source("kernel/include/socket_trace.h"))
        program = r"""
#include <assert.h>
#include <linux/types.h>
#include <stdbool.h>
#include <string.h>
struct pt_regs { int unused; };
struct data_args_t { unsigned int *msg_len; };
static struct { unsigned int length; unsigned int adjacent; } message;
static struct data_args_t arguments = { &message.length };
static bool read_failed;
static unsigned int submitted, deleted;
static __u32 observed;
static __u64 bpf_get_current_pid_tgid(void) { return 42; }
static struct data_args_t *active_@DIRECTION@_args_map__lookup(__u64 *id)
{
    assert(*id == 42);
    return &arguments;
}
static void active_@DIRECTION@_args_map__delete(__u64 *id)
{
    assert(*id == 42);
    deleted++;
}
static int bpf_probe_read_user(void *destination, unsigned int size, const void *source)
{
    assert(size == sizeof(message.length));
    if (read_failed)
        return -1;
    memcpy(destination, source, size);
    return 0;
}
static void process_syscall_data_vecs(struct pt_regs *ctx, __u64 id, int direction,
                                      struct data_args_t *args, __u32 length)
{
    assert(ctx && id == 42 && direction == 1 && args == &arguments);
    submitted++;
    observed = length;
}
static void exit_mmsg(struct pt_regs *ctx, int num_msgs)
{
@BODY@
}
int main(void)
{
    struct pt_regs context = { 0 };
    message.length = 37;
    message.adjacent = 0xdeadbeef;
    exit_mmsg(&context, 1);
    assert(submitted == 1 && observed == 37 && deleted == 1);
    message.length = 0xffffffff;
    exit_mmsg(&context, 2);
    assert(submitted == 2 && observed == 0xffffffff && deleted == 2);
    read_failed = true;
    exit_mmsg(&context, 1);
    assert(submitted == 3 && observed == 0 && deleted == 3);
    exit_mmsg(&context, 0);
    exit_mmsg(&context, -1);
    assert(submitted == 3 && deleted == 5);
    return 0;
}
"""
        compiler = shlex.split(os.environ.get("CC", "cc"))
        directory = tempfile.mkdtemp(prefix="mmsg-length-contracts-")
        try:
            for direction, tracepoint, value in (("write", "sendmmsg", "T_EGRESS"),
                                                  ("read", "recvmmsg", "T_INGRESS")):
                body = kernel.split("TP_SYSCALL_PROG(exit_" + tracepoint + ")", 1)[1]
                body = "\t__u64 id =" + body.split("\t__u64 id =", 1)[1].split("\n\treturn 0;", 1)[0]
                source = program.replace("@BODY@", body).replace("@DIRECTION@", direction)
                executable = os.path.join(directory, direction)
                process = subprocess.Popen(
                    compiler + ["-std=gnu99", "-Wall", "-Wextra", "-Werror", "-D" + value + "=1",
                                "-x", "c", "-", "-o", executable],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                stdout, stderr = process.communicate(source.encode("utf-8"))
                self.assertEqual(process.returncode, 0, (stdout + stderr).decode("utf-8"))
                subprocess.check_call([executable])
        finally:
            shutil.rmtree(directory)

    def test_output_only_and_unchanged_copy_path(self):
        kernel = read_source("kernel/socket_trace.bpf.c")
        rewrite = kernel.split("static_always_inline void\nrewrite_udp_peer_metadata", 1)[1]
        rewrite = rewrite.split("static __inline int finalize_data_output", 1)[0]
        for forbidden in ("socket_info_map", "trace_process", "reasm_bytes", "tail_call"):
            self.assertNotIn(forbidden, rewrite)
        self.assertEqual(kernel.count("if (!is_close)\n\t\trewrite_udp_peer_metadata(v, tracer_ctx, args);"), 2)
        peer_map = kernel.split('struct bpf_map_def SEC("maps") __udp_peer_map = {', 1)[1]
        peer_map = peer_map.split("};", 1)[0]
        self.assertIn("\n\t.type = BPF_MAP_TYPE_LRU_HASH,", peer_map)
        self.assertNotIn("BPF_MAP_TYPE_HASH", peer_map)
        self.assertNotIn("LINUX_VER_3_10_0", peer_map)
        user = read_source("user/socket.c")
        self.assertIn("static bool udp_peer_id_enabled = false;", user)
        self.assertIn("if (!udp_peer_id_enabled &&\n\t    (ret = maps_config(tracer, MAP_UDP_PEER_NAME, 1)))", user)
        self.assertIn("#define LOOP_LIMIT 18", kernel)
        self.assertNotIn("EXTRA_LOOP_LIMIT", kernel)
        extra = kernel.split("static __inline int output_extra_data_common", 1)[1]
        extra = extra.split("#if defined(LINUX_VER_KFUNC)", 1)[0]
        self.assertIn("extra_v->data_seq += 1;", extra)
        self.assertNotIn("udp_peer", extra)

    def test_real_metadata_rewrite(self):
        kernel = read_source("kernel/socket_trace.bpf.c")
        structures = kernel.split("struct udp_peer_key_t {", 1)[1]
        structures = "struct udp_peer_key_t {" + structures.split("/* *INDENT-OFF* */", 1)[0]
        common = read_source("kernel/include/socket_trace_common.h")
        tuple_definition = "struct __tuple_t {" + common.split("struct __tuple_t {", 1)[1].split("};", 1)[0] + "};"
        rewrite = kernel.split("static_always_inline void\nrewrite_udp_peer_metadata", 1)[1]
        rewrite = "static void\nrewrite_udp_peer_metadata" + rewrite.split(
            "static __inline int finalize_data_output", 1
        )[0]
        program = r"""
#include <assert.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#define PROTO_DNS 120
#define BPF_NOEXIST 1
@TUPLE@
struct __socket_data {
    __u64 socket_id;
    struct __tuple_t tuple;
    __u64 data_seq;
    __u16 data_type;
};
@STRUCTURES@
struct tracer_ctx_s { __u64 socket_id; };
struct data_args_t { __u64 extra_iovlen; };
struct test_entry {
    struct udp_peer_key_t key;
    struct udp_peer_state_t state;
};
static struct test_entry entries[16];
static unsigned int entry_count, peer_lookups;
static __u32 enabled;
static bool switch_missing, scratch_missing, update_failed, probe_read_failed;
static int __udp_peer_map;
static struct udp_peer_scratch_t scratch;
static __u32 *udp_peer_id_enabled_map__lookup(const __u32 *key)
{
    (void)key;
    return switch_missing ? NULL : &enabled;
}
static struct udp_peer_scratch_t *udp_peer_scratch__lookup(const __u32 *key)
{
    (void)key;
    return scratch_missing ? NULL : &scratch;
}
static void *bpf_map_lookup_elem(void *map, const struct udp_peer_key_t *key)
{
    (void)map;
    peer_lookups++;
    for (unsigned int index = 0; index < entry_count; index++)
        if (!memcmp(key, &entries[index].key, sizeof(*key)))
            return &entries[index].state;
    return NULL;
}
static int bpf_map_update_elem(void *map, const struct udp_peer_key_t *key,
                               const struct udp_peer_state_t *state, int flags)
{
    assert(flags == BPF_NOEXIST);
    if (update_failed || entry_count == 16 || bpf_map_lookup_elem(map, key))
        return -1;
    entries[entry_count].key = *key;
    entries[entry_count++].state = *state;
    return 0;
}
static int bpf_probe_read_kernel(void *destination, unsigned int size, const void *source)
{
    if (probe_read_failed)
        return -1;
    memcpy(destination, source, size);
    return 0;
}
@REWRITE@
static struct __socket_data event_for(unsigned int peer)
{
    struct __socket_data event = { 0 };
    event.tuple.rcv_saddr[0] = 127;
    event.tuple.rcv_saddr[3] = 1;
    event.tuple.daddr[0] = 127;
    event.tuple.daddr[3] = peer;
    event.tuple.addr_len = 4;
    event.tuple.l4_protocol = IPPROTO_UDP;
    event.tuple.num = 53053;
    event.tuple.dport = 40000;
    event.socket_id = 42;
    event.data_seq = 77;
    event.data_type = PROTO_DNS;
    return event;
}
static void unchanged(struct __socket_data event, struct tracer_ctx_s *context,
                      const struct data_args_t *args)
{
    struct __socket_data before = event;
    rewrite_udp_peer_metadata(&event, context, args);
    assert(!memcmp(&event, &before, sizeof(event)));
}
int main(void)
{
    struct tracer_ctx_s context = { 1000 };
    struct data_args_t args = { 0 };
    struct __socket_data first = event_for(2), second = event_for(3), current;
    unchanged(first, &context, &args);
    assert(context.socket_id == 1000 && peer_lookups == 0);
    enabled = 1;
    switch_missing = true;
    unchanged(first, &context, &args);
    switch_missing = false;
    current = first;
    current.tuple.l4_protocol = IPPROTO_TCP;
    unchanged(current, &context, &args);
    current = first;
    current.socket_id = 0;
    unchanged(current, &context, &args);
    current = first;
    current.tuple.num = 0;
    unchanged(current, &context, &args);
    current = first;
    current.tuple.dport = 0;
    unchanged(current, &context, &args);
    current = first;
    current.tuple.addr_len = 8;
    unchanged(current, &context, &args);
    current = first;
    memset(current.tuple.rcv_saddr, 0, 16);
    unchanged(current, &context, &args);
    current = first;
    memset(current.tuple.daddr, 0, 16);
    unchanged(current, &context, &args);
    assert(context.socket_id == 1000 && peer_lookups == 0);
    scratch_missing = true;
    unchanged(first, &context, &args);
    scratch_missing = false;
    probe_read_failed = true;
    unchanged(first, &context, &args);
    probe_read_failed = false;
    assert(context.socket_id == 1000 && peer_lookups == 0);
    memset(&scratch, 0xa5, sizeof(scratch));
    rewrite_udp_peer_metadata(&first, &context, &args);
    rewrite_udp_peer_metadata(&second, &context, &args);
    assert(first.socket_id != second.socket_id && first.socket_id != 42);
    assert(first.data_seq == 0 && second.data_seq == 0);
    current = event_for(2);
    memset(current.tuple.daddr + 4, 0xaa, 12);
    memset(current.tuple.rcv_saddr + 4, 0xbb, 12);
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.socket_id == first.socket_id && current.data_seq == 1);
    current = event_for(2);
    current.socket_id = 43;
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.socket_id != first.socket_id && current.data_seq == 0);
    current = event_for(4);
    args.extra_iovlen = 2;
    rewrite_udp_peer_metadata(&current, &context, &args);
    __u64 batch_id = current.socket_id;
    assert(current.data_seq == 0);
    struct __socket_data extra = current;
    extra.data_seq += 1;
    assert(extra.socket_id == batch_id && extra.data_seq == 1);
    current = event_for(4);
    args.extra_iovlen = 0;
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.socket_id == batch_id && current.data_seq == 2);
    args.extra_iovlen = 2;
    current = event_for(4);
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.data_seq == 3);
    args.extra_iovlen = 0;
    current = event_for(4);
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.data_seq == 5);
    args.extra_iovlen = 2;
    current = event_for(7);
    current.data_type = 0;
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.data_seq == 0);
    current = event_for(7);
    current.data_type = 0;
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.data_seq == 1);
    args.extra_iovlen = 0;
    current = event_for(5);
    current.tuple.addr_len = 16;
    memset(current.tuple.rcv_saddr, 0, 16);
    memset(current.tuple.daddr, 0, 16);
    unchanged(current, &context, &args);
    current.tuple.rcv_saddr[15] = 1;
    current.tuple.daddr[15] = 2;
    struct __socket_data ipv6 = current;
    rewrite_udp_peer_metadata(&ipv6, &context, &args);
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(ipv6.socket_id == current.socket_id && current.data_seq == 1);
    current = event_for(2);
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.socket_id == first.socket_id && current.data_seq == 2);
    update_failed = true;
    unchanged(event_for(6), &context, &args);
    update_failed = false;
    entry_count = 0;
    current = event_for(2);
    rewrite_udp_peer_metadata(&current, &context, &args);
    assert(current.socket_id != first.socket_id && current.data_seq == 0);
    enabled = 0;
    unchanged(event_for(2), &context, &args);
    return 0;
}
"""
        program = program.replace("@TUPLE@", tuple_definition).replace(
            "@STRUCTURES@", structures
        ).replace("@REWRITE@", rewrite)
        directory = tempfile.mkdtemp(prefix="udp-peer-id-contracts-")
        try:
            executable = os.path.join(directory, "contracts")
            compiler = shlex.split(os.environ.get("CC", "cc"))
            process = subprocess.Popen(
                compiler
                + [
                    "-std=gnu99", "-Wall", "-Wextra", "-Werror",
                    "-x", "c", "-", "-o", executable,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = process.communicate(program.encode("utf-8"))
            self.assertEqual(process.returncode, 0, (stdout + stderr).decode("utf-8"))
            subprocess.check_call([executable])
        finally:
            shutil.rmtree(directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
