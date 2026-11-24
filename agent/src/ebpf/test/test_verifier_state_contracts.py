import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_udp_peer_cache_contracts import read_source


class VerifierStateContracts(unittest.TestCase):
    def test_go_tls_read_sequence_scratch_scope(self):
        handler = read_source("kernel/go_tls.bpf.c").split(
            "UPROG(go_tls_read_exit) (struct pt_regs *ctx)", 1)[1]
        sequence = re.search(
            r"\n\t\{\n(\t\tstruct http2_tcp_seq_key tcp_seq_key = \{.*?\n)\t\}\n",
            handler, re.S,
        )
        self.assertIsNotNone(sequence)
        self.assertNotIn("process_data(", sequence.group(1))
        self.assertLess(sequence.end(), handler.index("process_data("))
        key_type = "struct http2_tcp_seq_key {" + read_source("kernel/uprobe_base.bpf.c").split(
            "struct http2_tcp_seq_key {", 1)[1].split("};", 1)[0] + "};"
        program = r"""
#include <assert.h>
#include <linux/types.h>
#include <stddef.h>
#define BPF_NOEXIST 1
@KEY_TYPE@
static unsigned char http2_tcp_seq_map;
static __u32 expected_sequence, expected_end;
static unsigned int reads, updates;
static __u32 get_tcp_read_seq(int descriptor, void *socket_info, void *offset)
{
    assert(descriptor == 19 && socket_info == NULL && offset == NULL);
    reads++;
    return expected_end;
}
static int bpf_map_update_elem(const void *map, const struct http2_tcp_seq_key *key,
                               const __u32 *sequence, unsigned long flags)
{
    assert(map == &http2_tcp_seq_map && flags == BPF_NOEXIST);
    assert(key->tgid == 17 && key->fd == 19 && key->tcp_seq_end == expected_end);
    assert(*sequence == expected_sequence);
    updates++;
    return 0;
}
int main(void)
{
    struct { int tgid; } key = {17};
    struct { int fd; __u32 tcp_seq; } connection = {19, 0}, *c = &connection;
    const __u32 sequences[] = {0, 1, 0x7fffffff, 0x80000000, 0xffffffff};
    for (unsigned int index = 0; index < sizeof(sequences) / sizeof(sequences[0]); index++) {
        expected_sequence = connection.tcp_seq = sequences[index];
        expected_end = sequences[index] + 31;
        reads = updates = 0;
        {
@SEQUENCE@
        }
        assert(reads == 1 && updates == 1);
    }
    return 0;
}
""".replace("@KEY_TYPE@", key_type).replace("@SEQUENCE@", sequence.group(1))
        compiler = shlex.split(os.environ.get("CC", "cc"))
        directory = tempfile.mkdtemp(prefix="go-tls-sequence-contracts-")
        try:
            executable = os.path.join(directory, "sequence")
            result = subprocess.Popen(
                compiler + ["-std=gnu99", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-x", "c", "-", "-o", executable],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout, stderr = result.communicate(program.encode("utf-8"))
            self.assertEqual(result.returncode, 0, (stdout + stderr).decode("utf-8"))
            subprocess.check_call([executable])
        finally:
            shutil.rmtree(directory)

    def test_real_state_normalization(self):
        kernel = read_source("kernel/socket_trace.bpf.c")
        process = kernel.split("static __inline int process_data(", 1)[1].split(
            "static __inline void process_syscall_data(", 1)[0]
        blocks = re.findall(r"(?m)^\s*#if defined\(LINUX_VER_5_2_PLUS\)\n.*?^\s*#endif", process, re.S)
        self.assertEqual(len(blocks), 3)
        self.assertIn("ctx_map->bytes_count", blocks[0])
        self.assertNotIn("extra->vecs", blocks[0])
        self.assertIn("offsetof(struct conn_info_s, socket_info_ptr)", blocks[1])
        self.assertNotIn("extra->vecs", blocks[1])
        self.assertIn("conn_info->socket_info_ptr = socket_info_ptr;", blocks[2])
        self.assertIn("if (extra->vecs) {", blocks[2])
        self.assertNotIn("bpf_tail_call", "".join(blocks))
        header = read_source("kernel/include/socket_trace.h")
        tuple_type = "struct __tuple_t {" + read_source("kernel/include/socket_trace_common.h").split(
            "struct __tuple_t {", 1)[1].split("};", 1)[0] + "};"
        structures = "struct conn_info_s {" + header.split("struct conn_info_s {", 1)[1].split(
            "enum syscall_src_func", 1)[0]
        cache_size = re.search(r"#define EBPF_CACHE_SIZE\s+(\d+)", read_source("kernel/include/common.h")).group(1)
        program = r"""
#include <assert.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#define EBPF_CACHE_SIZE @CACHE_SIZE@
enum traffic_protocol { TEST_PROTOCOL };
enum traffic_direction { TEST_DIRECTION };
enum process_data_extra_source { TEST_SOURCE };
enum message_type { TEST_MESSAGE };
struct socket_info_s { __u64 uid; };
@TUPLE@
@STRUCTURES@
_Static_assert(sizeof(struct ctx_info_s) == sizeof(struct tail_calls_context), "context size unchanged");
_Static_assert(offsetof(struct ctx_info_s, infer_buf) == 0, "inference offset unchanged");
_Static_assert(offsetof(struct ctx_info_s, bytes_count) >= sizeof(struct infer_data_s), "no inference overlap");
static unsigned int probes;
static bool fail_probe;
static size_t last_size;
static int bpf_probe_read_kernel(void *destination, size_t size, const void *source)
{
    assert(destination == source);
    probes++;
    last_size = size;
    if (fail_probe) {
        memset(destination, 0, size);
        return -1;
    }
    memmove(destination, source, size);
    return 0;
}
static int normalize(struct ctx_info_s *ctx_map, struct conn_info_s *conn_info, ssize_t *value)
{
    ssize_t bytes_count = *value;
@COUNT@
@PRE@
    *value = bytes_count;
    return 0;
}
static int finish(struct conn_info_s *conn_info, const struct process_data_extra *extra)
{
@POST@
    return 0;
}
int main(void)
{
    struct ctx_info_s context;
    struct conn_info_s connection, original;
    struct socket_info_s state = { 17 };
    const __u64 values[] = {0, 1, 31, 0x7fffffff, 0xffffffff, 1ULL << 40,
                            0x7fffffffffffffffULL, 1ULL << 63, UINT64_MAX};
    for (unsigned int variant = 0; variant < 4; variant++) {
        struct process_data_extra extra = { .vecs = variant & 1 };
        bool present = (variant & 2) != 0;
        for (unsigned int index = 0; index < sizeof(values) / sizeof(values[0]); index++) {
            memset(&context, 0x33, sizeof(context));
            memset(&connection, 0xa5, sizeof(connection));
            connection.socket_info_ptr = present ? &state : NULL;
            memcpy(&original, &connection, sizeof(original));
            unsigned char inference[sizeof(context.infer_buf)];
            memcpy(inference, &context.infer_buf, sizeof(inference));
            ssize_t value = (ssize_t)values[index];
            probes = 0;
            assert(normalize(&context, &connection, &value) == 0);
            assert((__u64)value == values[index]);
            assert(memcmp(&connection, &original, sizeof(connection)) == 0);
            assert(memcmp(&context.infer_buf, inference, sizeof(inference)) == 0);
#if defined(LINUX_VER_5_2_PLUS)
            assert(context.bytes_count == values[index]);
            assert(probes == 1 && last_size == offsetof(struct conn_info_s, socket_info_ptr));
#else
            assert(probes == 0);
#endif
            assert(finish(&connection, &extra) == 0);
            assert(memcmp(&connection, &original, sizeof(connection)) == 0);
#if defined(LINUX_VER_5_2_PLUS)
            assert(probes == (extra.vecs ? 2U : 1U));
            assert(last_size == (extra.vecs ? sizeof(connection) : offsetof(struct conn_info_s, socket_info_ptr)));
#else
            assert(probes == 0);
#endif
            fail_probe = true;
#if defined(LINUX_VER_5_2_PLUS)
            assert(normalize(&context, &connection, &value) == -1);
            memcpy(&connection, &original, sizeof(connection));
            assert(finish(&connection, &extra) == (extra.vecs ? -1 : 0));
#else
            assert(normalize(&context, &connection, &value) == 0);
            assert(finish(&connection, &extra) == 0);
#endif
            fail_probe = false;
        }
    }
    return 0;
}
""".replace("@CACHE_SIZE@", cache_size).replace("@TUPLE@", tuple_type).replace("@STRUCTURES@", structures).replace(
            "@COUNT@", blocks[0]).replace("@PRE@", blocks[1]).replace("@POST@", blocks[2])
        compiler = shlex.split(os.environ.get("CC", "cc"))
        directory = tempfile.mkdtemp(prefix="verifier-state-contracts-")
        try:
            for variant in ("COMMON", "LINUX_VER_5_2_PLUS", "LINUX_VER_KFUNC"):
                executable = os.path.join(directory, variant)
                result = subprocess.Popen(
                    compiler + ["-std=gnu99", "-O2", "-Wall", "-Wextra", "-Werror",
                                "-Wno-unused-parameter", "-Wno-unused-function", "-D" + variant,
                                "-x", "c", "-", "-o", executable],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                stdout, stderr = result.communicate(program.encode("utf-8"))
                self.assertEqual(result.returncode, 0, (stdout + stderr).decode("utf-8"))
                subprocess.check_call([executable])
        finally:
            shutil.rmtree(directory)


if __name__ == "__main__":
    unittest.main(verbosity=2)
