#!/usr/bin/env python3

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
KERNEL = (ROOT / "kernel/socket_trace.bpf.c").read_text(encoding="utf-8")
SOCKET_HEADER = (ROOT / "kernel/include/socket_trace.h").read_text(encoding="utf-8")
SOCKET_COMMON = (ROOT / "kernel/include/socket_trace_common.h").read_text(
    encoding="utf-8"
)
SOCKET_USER = (ROOT / "user/socket.c").read_text(encoding="utf-8")
SOCKET_USER_HEADER = (ROOT / "user/socket.h").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def block(source: str, begin: str, end: str) -> str:
    start = source.find(begin)
    require(start != -1, f"missing {begin}")
    finish = source.find(end, start)
    require(finish != -1, f"missing end marker {end}")
    return source[start:finish]


data_args = block(
    SOCKET_HEADER, "struct data_args_t {", "struct syscall_comm_enter_ctx"
)
require(
    "udp_local_addr" not in data_args,
    "UDP compensation must not enlarge the syscall stack argument structure",
)
require(
    "地址缓冲区的入口容量" in data_args,
    "the existing port field must document its temporary sockaddr capacity use",
)
sendmmsg_exit = block(
    KERNEL, "KRETPROG(__sys_sendmmsg)", "// BSD recvmsg interface"
)
recvmmsg_exit = block(
    KERNEL, "KRETPROG(__sys_recvmmsg)", "//static ssize_t do_writev"
)
for function_name, mmsg_exit in (
    ("sendmmsg", sendmmsg_exit),
    ("recvmmsg", recvmmsg_exit),
):
    require(
        "ssize_t bytes_count = 0;" in mmsg_exit
        and "bpf_probe_read_user(&bytes_count, sizeof(unsigned int)," in mmsg_exit
        and "sizeof(bytes_count)" not in mmsg_exit
        and "sizeof(write_args->msg_len)" not in mmsg_exit
        and "sizeof(read_args->msg_len)" not in mmsg_exit,
        f"{function_name} must keep a zeroed ssize_t slot but read only the 32-bit mmsghdr.msg_len value",
    )

sendmmsg_entry = block(
    KERNEL, "KPROG(__sys_sendmmsg)", "KRETPROG(__sys_sendmmsg)"
)
require(
    "extract_network_address_info" in sendmmsg_entry
    and "msgvec[0].msg_hdr.msg_name" in sendmmsg_entry
    and "msgvec[0].msg_hdr.msg_namelen" in sendmmsg_entry,
    "sendmmsg must extract the first destination using its declared address length",
)
require(
    "if (num_msgs < 2)" in sendmmsg_exit
    and "write_args->extra_iovlen = 0" in sendmmsg_exit
    and sendmmsg_exit.find("write_args->extra_iovlen = 0")
    < sendmmsg_exit.find("process_syscall_data_vecs"),
    "sendmmsg must suppress the second event when fewer than two messages succeeded",
)

extra_output = block(
    KERNEL,
    "static_always_inline int output_extra_data_common",
    "#if defined(LINUX_VER_KFUNC)",
)
require(
    "(char *)args->msg_len + sizeof(struct mmsghdr)" in extra_output
    and "bpf_probe_read_user(&extra_v->syscall_len," in extra_output
    and "sizeof(extra_v->syscall_len), msg_len)" in extra_output
    and "unsigned int syscall_len" not in extra_output
    and extra_output.find("bpf_probe_read_user(&extra_v->syscall_len,")
    < extra_output.find("output_iov_data_copy"),
    "the second sendmmsg event must read its length directly into the event before copying data",
)
recvmmsg_entry = block(
    KERNEL, "KPROG(__sys_recvmmsg)", "KRETPROG(__sys_recvmmsg)"
)
require(
    recvmmsg_entry.count("read_args.ipaddr_ptr") >= 1
    and recvmmsg_entry.count("offsetof(typeof(struct user_msghdr), msg_name)") >= 1
    and recvmmsg_entry.count("offsetof(typeof(struct user_msghdr), msg_namelen)") >= 1
    and recvmmsg_entry.count("normalize_sockaddr_capacity(msg_namelen)") >= 1,
    "all recvmmsg entry variants must retain the source buffer and its input capacity",
)
require(
    "__u16 addr_len = read_args->port" in recvmmsg_exit
    and "read_args->ipaddr_ptr = NULL" in recvmmsg_exit
    and "extract_network_address_info(read_args, ipaddr_ptr, addr_len)"
    in recvmmsg_exit,
    "recvmmsg must validate the returned address using the saved input capacity",
)
require(
    recvmmsg_exit.find("read_args->ipaddr_ptr = NULL")
    < recvmmsg_exit.find("extract_network_address_info"),
    "recvmmsg must clear the shared address/pointer union before extraction",
)

address_capacity = block(
    KERNEL,
    "static __inline __u16 normalize_sockaddr_capacity",
    "static __inline void extract_network_address_info",
)
require(
    "SOCKADDR_IN6_ADDR_PORT_LEN" in address_capacity
    and "sizeof(struct sockaddr_in6)" not in address_capacity,
    "receive capacity normalization must accept the 24-byte IPv6 address layout",
)

address_extract = block(
    KERNEL,
    "static __inline void extract_network_address_info",
    "/* *INDENT-OFF* */",
)
require(
    "args->port = 0" in address_extract
    and "addr_len < (int)sizeof(struct sockaddr_in)" in address_extract
    and "addr_len >= (int)SOCKADDR_IN6_ADDR_PORT_LEN" in address_extract,
    "sockaddr extraction must clear stale state and validate IPv4/IPv6 lengths",
)
require(
    "offsetof(struct sockaddr_in6, sin6_scope_id)" in KERNEL
    and "bpf_probe_read_user(&addr6, SOCKADDR_IN6_ADDR_PORT_LEN, ptr)"
    in address_extract
    and "bpf_probe_read_user(&addr6, sizeof(addr6), ptr)" not in address_extract,
    "IPv6 extraction must read only the 24 bytes containing the address and port",
)
require(
    "*(__u64 *) &args->addr[0] = 0" in address_extract
    and "*(__u32 *) &args->addr[8] = 0xffff0000" in address_extract
    and "*(__u32 *) &args->addr[12] = addr.sin_addr.s_addr" in address_extract,
    "IPv4 sockaddr values must be normalized to IPv4-mapped form",
)

data_submit = block(
    KERNEL,
    "static __inline int\n__data_submit",
    "static __inline int process_data(",
)
mapped_address_check = data_submit.find(
    "*(__u32 *) & v->tuple.daddr[8] == 0xffff0000"
)
socket_family_check = data_submit.find("conn_info->skc_family == PF_INET")
require(
    mapped_address_check != -1
    and socket_family_check != -1
    and mapped_address_check < socket_family_check
    and "bpf_probe_read_kernel(v->tuple.daddr, sizeof(args->addr)," in data_submit
    and "*(__u32 *) & v->tuple.daddr[12]" in data_submit,
    "UDP output must recognize IPv4-mapped addresses before using the socket family",
)

sendmsg_entry = block(KERNEL, "KPROG(__sys_sendmsg)", "KRETPROG(__sys_sendmsg)")
require(
    "msghdr->msg_namelen" in sendmsg_entry
    and "write_args.ipaddr_ptr" not in sendmsg_entry,
    "sendmsg must validate msg_name at entry instead of retaining an unchecked pointer",
)

sendto_entry = block(
    KERNEL,
    "static __inline int do_sys_enter_sendto",
    "// System call sendto() exit point",
)
require(
    "addr_len = sendto_ctx->addr_len" in sendto_entry
    and "PT_REGS_PARM6(ctx)" in sendto_entry
    and "defined(SUPPORTS_KPROBE_ONLY)" in sendto_entry
    and "extract_network_address_info(&write_args, ptr, addr_len)" in sendto_entry
    and "sizeof(struct sockaddr_in6)" not in sendto_entry,
    "sendto must validate the destination using the syscall's actual addr_len",
)

recvmsg_entry = block(KERNEL, "KPROG(__sys_recvmsg)", "KRETPROG(__sys_recvmsg)")
require(
    "normalize_sockaddr_capacity(msghdr->msg_namelen)" in recvmsg_entry,
    "recvmsg must retain the input msg_name capacity",
)
recvmsg_exit = block(
    KERNEL,
    "KRETPROG(__sys_recvmsg)",
    "//int __sys_recvmmsg",
)
require(
    "read_args->ipaddr_ptr = NULL" in recvmsg_exit
    and recvmsg_exit.find("read_args->ipaddr_ptr = NULL")
    < recvmsg_exit.find("extract_network_address_info"),
    "recvmsg must clear the shared address/pointer union before extraction",
)

recvfrom_entry = block(
    KERNEL,
    "static __inline int do_sys_enter_recvfrom",
    "// System call recvfrom() exit point",
)
require(
    "bpf_probe_read_user(&addr_len" in recvfrom_entry
    and "normalize_sockaddr_capacity(addr_len)" in recvfrom_entry
    and recvfrom_entry.count("PT_REGS_PARM6(ctx)") == 2
    and "struct syscall_recvfrom_enter_ctx" in recvfrom_entry,
    "all recvfrom entry variants must retain the input sockaddr capacity",
)
recvfrom_exit = block(
    KERNEL,
    "static __inline int do_sys_exit_recvfrom",
    "#ifdef SUPPORTS_KPROBE_ONLY",
)
require(
    "__u16 addr_len = read_args->port" in recvfrom_exit
    and "extract_network_address_info(read_args, ptr, addr_len)" in recvfrom_exit
    and "sizeof(struct sockaddr_in6)" not in recvfrom_exit,
    "recvfrom must validate the returned address using the saved input capacity",
)

process_data = block(
    KERNEL, "static __inline int process_data(", "static __inline void process_syscall_data("
)
require(
    "conn_info->tuple.l4_protocol == IPPROTO_UDP && args->port > 0"
    in process_data
    and "conn_info->tuple.dport = args->port" in process_data
    and "udp_pre_set_addr" not in process_data,
    "UDP tuples must use only the current syscall address and never cached peer state",
)
require(
    "udp_pre_set_addr" not in KERNEL
    and "sk_info->ipaddr" not in KERNEL
    and "sk_info->port" not in KERNEL,
    "socket_info_map must not cache per-datagram UDP peer addresses",
)
require(
    "reserved_udp_addr_cache:1" in SOCKET_COMMON
    and "reserved_udp_addr[EBPF_CACHE_SIZE]" in SOCKET_COMMON
    and "reserved_udp_port" in SOCKET_COMMON,
    "legacy UDP cache storage must remain reserved to preserve the map value ABI",
)

require(
    "__u16 source_fn" in data_args and "__u16 mmsg_count" in data_args,
    "syscall arguments must reuse the original enum storage for mmsg metadata",
)
kernel_socket_data = block(
    SOCKET_COMMON, "struct __socket_data {", "struct __socket_data_buffer"
)
require(
    "__u32 syscall_len" in kernel_socket_data
    and "__u8 source_fn" in kernel_socket_data
    and "__u8 reserved_syscall_meta" in kernel_socket_data
    and "__u16 mmsg_count" in kernel_socket_data,
    "kernel socket events must reuse the upper half of the old syscall length field",
)
public_socket_data = block(
    SOCKET_USER_HEADER, "struct socket_bpf_data {", "struct socket_trace_stats"
)
require(
    "uint64_t syscall_len" in public_socket_data
    and "source_fn" not in public_socket_data
    and "mmsg_count" not in public_socket_data,
    "the public socket callback ABI must remain unchanged",
)
require(
    "v->source_fn = (__u8)args->source_fn" in data_submit
    and "v->mmsg_count = args->mmsg_count" in data_submit,
    "socket events must carry syscall source and successful mmsg count",
)
require(
    "write_args->mmsg_count = (__u16)num_msgs" in sendmmsg_exit
    and "read_args->mmsg_count = (__u16)num_msgs" in recvmmsg_exit,
    "mmsg exits must record the successful message count returned by the syscall",
)
require(
    "if (sd->source == DATA_SOURCE_SYSCALL)" in SOCKET_USER
    and "(uint64_t)sd->mmsg_count << 32" in SOCKET_USER
    and "(uint64_t)sd->source_fn << 48" in SOCKET_USER,
    "userspace must encode datadump metadata only for syscall events",
)
require(
    "SOURCE_FN %s(%u) MSG_NUM %u" in SOCKET_USER
    and "syscall_source_name(source_fn)" in SOCKET_USER,
    "datadump must display the syscall source and mmsg count",
)
require(
    "sd->syscall_len = (uint32_t)sd->syscall_len" in SOCKET_USER_HEADER,
    "datadump metadata must be removed before invoking the public callback",
)

print("[OK] UDP syscall address contracts")
