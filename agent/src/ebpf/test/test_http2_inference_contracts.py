import os
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_udp_peer_cache_contracts import read_source


class Http2InferenceContracts(unittest.TestCase):
    def test_variant_fast_matching(self):
        source = read_source("kernel/include/protocol_inference.h")
        inference = "infer_protocol_1(" + source.split("infer_protocol_1(", 1)[1].rsplit("#endif", 1)[0]
        compiler = shlex.split(os.environ.get("CC", "cc"))
        for variant, definitions, cache_enabled, chained in (
            ("common", [], False, False),
            ("5_2_plus", ["-DLINUX_VER_5_2_PLUS"], True, True),
            ("kfunc", ["-DLINUX_VER_KFUNC"], True, True),
        ):
            process = subprocess.Popen(
                compiler + ["-E", "-P", "-x", "c", "-"] + definitions,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout, stderr = process.communicate(inference.encode("utf-8"))
            self.assertEqual(process.returncode, 0, (variant, stderr.decode("utf-8")))
            expanded = stdout.decode("utf-8")
            self.assertEqual("proto_infer_cache_map__lookup" in expanded, cache_enabled, variant)
            self.assertEqual("infer_protocol_2" in expanded, chained, variant)
            for protocol in ("infer_http_message", "infer_http2_message", "infer_dns_message", "infer_redis_message"):
                self.assertIn(protocol, expanded)
        kernel = read_source("kernel/socket_trace.bpf.c")
        self.assertIn("struct conn_info_s *conn_info, __conn_info = { 0 };", kernel)

    def test_real_http2_inference(self):
        source = read_source("kernel/include/protocol_inference.h")
        helpers = "static __inline __u8 get_block_fragment_offset" + source.split(
            "static __inline __u8 get_block_fragment_offset", 1
        )[1].split("static __inline enum message_type infer_http_message", 1)[0]
        validity = "static __inline bool is_infer_socket_valid" + source.split(
            "static __inline bool is_infer_socket_valid", 1
        )[1].split("// When calling this function", 1)[0]
        self.assertNotIn("bpf_tail_call", helpers)
        self.assertIn("#define HTTPV2_LOOP_MAX 8", helpers)
        self.assertIn("#define HTTPV2_LOOP_MAX 5", helpers)
        program = r"""
#include <arpa/inet.h>
#include <assert.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#define __bpf_ntohl ntohl
#define BPF_NOEXIST 1
#define PROTO_UNKNOWN 0
#define PROTO_HTTP1 20
#define PROTO_HTTP2 21
#define PROTO_TLS 121
enum message_type { MSG_UNKNOWN, MSG_REQUEST, MSG_RESPONSE, MSG_PRESTORE };
enum { T_EGRESS, T_INGRESS, ROLE_UNKNOWN, ROLE_CLIENT, ROLE_SERVER };
struct socket_info_s { __u64 uid; int l7_proto; };
struct conn_info_s {
    struct socket_info_s *socket_info_ptr;
    struct { int l4_protocol; } tuple;
    size_t prev_count;
    int direction, role, fd;
};
struct http2_tcp_seq_key { __u32 tgid, fd, tcp_seq_end; };
static bool ports_enabled = true, skip_http2;
static unsigned int saved_count, updates;
static char saved_data[9];
static int http2_tcp_seq_map;
static __u32 saved_seq;
static struct http2_tcp_seq_key saved_key;
static bool protocol_port_check_1(int protocol, struct conn_info_s *connection)
{ return ports_enabled; }
static bool skip_http2_kprobe(void) { return skip_http2; }
static __u64 bpf_get_current_pid_tgid(void) { return 0x1200000034ULL; }
static __u32 get_tcp_read_seq(int descriptor, void *socket, void *state) { return 100; }
static int bpf_map_update_elem(void *map, const void *key, const void *value, int flags)
{
    saved_key = *(const struct http2_tcp_seq_key *)key;
    saved_seq = *(const __u32 *)value;
    updates++;
    return 0;
}
static int bpf_probe_read_user(void *destination, size_t size, const void *source)
{ memcpy(destination, source, size); return 0; }
static void save_prev_data_from_kern(const char *buffer, struct conn_info_s *connection, size_t count)
{ saved_count = count; memcpy(saved_data, buffer, count); }
@VALIDITY@
@HELPERS@
static void frame(unsigned char *buffer, unsigned int offset, unsigned char type)
{
    memset(buffer + offset, 0, 21);
    buffer[offset + 2] = 12;
    buffer[offset + 3] = type;
    buffer[offset + 8] = 1;
    buffer[offset + 9] = 0x82;
}
static enum message_type infer(unsigned char *buffer, size_t syscall_len,
                               size_t count, struct conn_info_s *connection)
{
    return infer_http2_message((const char *)buffer, syscall_len,
                              (const char *)buffer, count, connection);
}
int main(void)
{
    assert(HTTPV2_LOOP_MAX == EXPECTED_FRAME_LIMIT);
    char magic[25] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert(is_http2_magic(magic, 24));
    for (unsigned int index = 0; index < 12; index++) {
        magic[index] ^= 1;
        assert(!is_http2_magic(magic, 24));
        magic[index] ^= 1;
    }
    for (unsigned int padding = 0; padding < 256; padding++)
        for (unsigned int priority = 0; priority < 256; priority++)
            assert(get_block_fragment_offset(9, padding, priority) ==
                   9 + (padding != 0) + 5 * (priority != 0));
    unsigned char fragments[256];
    for (unsigned int offset = 0; offset < 256; offset++)
        for (unsigned int index = 0; index < 6; index++)
            for (unsigned int value = 0; value < 256; value++) {
                memset(fragments, 0xff, sizeof(fragments));
                fragments[(unsigned char)(offset + index)] = value;
                unsigned char expected = fragments[offset] & 0x7f;
                for (unsigned int step = 1; step < 6; step++)
                    if (expected == 0 || expected > 61)
                        expected = fragments[(unsigned char)(offset + step)] & 0x7f;
                assert(find_idx_from_block_fragment(fragments, offset, 61) == expected);
            }
    unsigned char buffer[512] = {0};
    struct socket_info_s state = { .uid = 1, .l7_proto = PROTO_HTTP2 };
    struct conn_info_s connection = { .tuple.l4_protocol = IPPROTO_TCP,
                                     .direction = T_INGRESS, .fd = 7 };
    frame(buffer, 0, 1);
    assert(infer(buffer, 21, 21, &connection) == MSG_REQUEST);
    assert(connection.role == ROLE_SERVER);
    connection.direction = T_EGRESS;
    assert(infer(buffer, 21, 21, &connection) == MSG_REQUEST);
    assert(connection.role == ROLE_CLIENT);
    buffer[9] = 0x88;
    assert(infer(buffer, 21, 21, &connection) == MSG_RESPONSE);
    assert(connection.role == ROLE_SERVER);
    connection.direction = T_INGRESS;
    assert(infer(buffer, 21, 21, &connection) == MSG_RESPONSE);
    assert(connection.role == ROLE_CLIENT);
    for (unsigned int flags = 0; flags < 4; flags++) {
        frame(buffer, 0, 1);
        buffer[4] = (flags & 1 ? 8 : 0) | (flags & 2 ? 32 : 0);
        memset(buffer + 9, 0, 12);
        buffer[9 + (flags & 1 ? 1 : 0) + (flags & 2 ? 5 : 0)] = 0x82;
        assert(infer(buffer, 21, 21, &connection) == MSG_REQUEST);
    }
    for (unsigned int index = 0; index <= HTTPV2_LOOP_MAX; index++)
        frame(buffer, index * 21, 4);
    frame(buffer, (HTTPV2_LOOP_MAX - 1) * 21, 1);
    assert(infer(buffer, sizeof(buffer), HTTPV2_LOOP_MAX * 21, &connection) == MSG_REQUEST);
    frame(buffer, (HTTPV2_LOOP_MAX - 1) * 21, 4);
    frame(buffer, HTTPV2_LOOP_MAX * 21, 1);
    assert(infer(buffer, sizeof(buffer), (HTTPV2_LOOP_MAX + 1) * 21, &connection) == MSG_UNKNOWN);
    memmove(buffer + 24, buffer, (HTTPV2_LOOP_MAX + 1) * 21);
    memcpy(buffer, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24);
    frame(buffer, 24 + (HTTPV2_LOOP_MAX - 1) * 21, 1);
    assert(infer(buffer, sizeof(buffer), 24 + HTTPV2_LOOP_MAX * 21, &connection) == MSG_REQUEST);
    frame(buffer, 0, 0);
    connection.socket_info_ptr = &state;
    assert(infer(buffer, 21, 21, &connection) == MSG_REQUEST);
    state.l7_proto = PROTO_HTTP1;
    assert(infer(buffer, 21, 21, &connection) == MSG_UNKNOWN);
    frame(buffer, 0, 1);
    state.l7_proto = PROTO_TLS;
    assert(infer(buffer, 21, 21, &connection) == MSG_REQUEST);
    state.l7_proto = PROTO_UNKNOWN;
    assert(infer(buffer, 21, 21, &connection) == MSG_REQUEST);
    connection.socket_info_ptr = NULL;
    frame(buffer, 0, 1);
    buffer[2] = 0;
    assert(infer(buffer, 9, 9, &connection) == MSG_PRESTORE);
    assert(saved_count == 9 && !memcmp(saved_data, buffer, 9));
    connection.prev_count = 9;
    assert(infer(buffer, 0, 0, &connection) == MSG_REQUEST);
    connection.prev_count = 0;
    assert(infer(buffer, 8, 8, &connection) == MSG_UNKNOWN);
    frame(buffer, 0, 1);
    buffer[4] = 2;
    assert(infer(buffer, 21, 21, &connection) == MSG_UNKNOWN);
    buffer[4] = 0;
    buffer[5] = 0x80;
    assert(infer(buffer, 21, 21, &connection) == MSG_UNKNOWN);
    ports_enabled = false;
    assert(infer(buffer, 21, 21, &connection) == MSG_UNKNOWN);
    ports_enabled = true;
    skip_http2 = true;
    assert(infer(buffer, 21, 21, &connection) == MSG_UNKNOWN);
    assert(updates == 1 && saved_key.tgid == 0x12 && saved_key.fd == 7);
    assert(saved_key.tcp_seq_end == 100 && saved_seq == 79);
    connection.direction = T_EGRESS;
    assert(infer(buffer, 21, 21, &connection) == MSG_UNKNOWN);
    assert(updates == 1);
    return 0;
}
"""
        program = program.replace("@VALIDITY@", validity).replace("@HELPERS@", helpers)
        directory = tempfile.mkdtemp(prefix="http2-inference-contracts-")
        try:
            compiler = shlex.split(os.environ.get("CC", "cc"))
            for variant, definitions in (
                ("common", ["-DEXPECTED_FRAME_LIMIT=5"]),
                ("5_2_plus", ["-DLINUX_VER_5_2_PLUS", "-DEXPECTED_FRAME_LIMIT=8"]),
                ("kfunc", ["-DLINUX_VER_KFUNC", "-DEXPECTED_FRAME_LIMIT=8"]),
            ):
                executable = os.path.join(directory, variant)
                process = subprocess.Popen(
                    compiler + ["-std=gnu99", "-Wall", "-Wextra", "-Werror",
                                "-Wno-unused-parameter", "-Wno-sign-compare",
                                "-Wno-unknown-pragmas"] + definitions
                    + ["-x", "c", "-", "-o", executable],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                stdout, stderr = process.communicate(program.encode("utf-8"))
                self.assertEqual(process.returncode, 0, (variant, (stdout + stderr).decode("utf-8")))
                subprocess.check_call([executable])
        finally:
            shutil.rmtree(directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
