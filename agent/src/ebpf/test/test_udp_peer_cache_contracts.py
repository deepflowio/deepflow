import io
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


EBPF_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_source(relative_path):
    with io.open(os.path.join(EBPF_ROOT, relative_path), encoding="utf-8") as source:
        return source.read()


class UdpPeerCacheContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kernel = read_source("kernel/socket_trace.bpf.c")
        cls.common = read_source("kernel/include/socket_trace_common.h")

    def test_no_historical_peer_reads_or_writes(self):
        self.assertFalse(
            "udp_pre_set_addr" in self.kernel,
            "UDP tuples must not depend on historical peer addresses",
        )
        self.assertIsNone(
            re.search(r"\b(?:sk_info|socket_info_ptr)\s*->\s*(?:ipaddr|port)\b", self.kernel)
        )

    def test_legacy_storage_is_reserved(self):
        for declaration in (
            r"__u16\s+reserved_udp_addr_cache\s*:\s*1\s*;",
            r"__u8\s+reserved_udp_addr\s*\[EBPF_CACHE_SIZE\]\s*;",
            r"__u16\s+reserved_udp_port\s*;",
        ):
            self.assertIsNotNone(re.search(declaration, self.common))

    def test_actual_port_selection_and_map_layout(self):
        process_data = self.kernel.split("static __inline int process_data(", 1)[1]
        selection = process_data.split("bytes_count, offset);", 1)[1].split(
            "conn_info->direction = direction;", 1
        )[0]
        socket_info = re.search(
            r"struct socket_info_s \{.*?\} __attribute__ \(\(packed\)\);",
            self.common,
            re.S,
        ).group(0)
        cache_size = re.search(
            r"#define\s+EBPF_CACHE_SIZE\s+(\d+)",
            read_source("kernel/include/common.h"),
        ).group(1)
        program = r"""
#include <assert.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#define EBPF_CACHE_SIZE @CACHE_SIZE@
@SOCKET_INFO@

struct test_tuple {
    unsigned int l4_protocol;
    unsigned short dport;
};

struct test_conn_info {
    struct test_tuple tuple;
};

struct test_data_args {
    unsigned short port;
};

static unsigned short select_remote_port(unsigned int protocol,
                                        unsigned short kernel_port,
                                        unsigned short syscall_port)
{
    struct test_conn_info connection = { { protocol, kernel_port } };
    struct test_conn_info *conn_info = &connection;
    struct test_data_args arguments = { syscall_port };
    struct test_data_args *args = &arguments;
    @SELECTION@
    return conn_info->tuple.dport;
}

int main(void)
{
    assert(select_remote_port(IPPROTO_UDP, 0, 53001) == 53001);
    assert(select_remote_port(IPPROTO_UDP, 0, 53002) == 53002);
    assert(select_remote_port(IPPROTO_UDP, 0, 0) == 0);
    assert(select_remote_port(IPPROTO_UDP, 53, 0) == 53);
    assert(select_remote_port(IPPROTO_TCP, 443, 53) == 443);
    assert(sizeof(struct socket_info_s) == 82);
    assert(offsetof(struct socket_info_s, reasm_bytes) == 20);
    assert(offsetof(struct socket_info_s, seq) == 24);
    assert(offsetof(struct socket_info_s, prev_data) == 32);
    assert(offsetof(struct socket_info_s, encoding_type) == 50);
    assert(offsetof(struct socket_info_s, correlation_id) == 50);
    assert(offsetof(struct socket_info_s, peer_fd) == 54);
    assert(offsetof(struct socket_info_s, update_time) == 58);
    assert(offsetof(struct socket_info_s, prev_data_len) == 62);
    assert(offsetof(struct socket_info_s, trace_id) == 66);
    assert(offsetof(struct socket_info_s, uid) == 74);
    return 0;
}
"""
        program = program.replace("@CACHE_SIZE@", cache_size)
        program = program.replace("@SOCKET_INFO@", socket_info)
        program = program.replace("@SELECTION@", selection)
        directory = tempfile.mkdtemp(prefix="udp-peer-cache-contracts-")
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
