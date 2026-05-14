#!/usr/bin/env python3

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOCKET_TRACE = ROOT / "kernel" / "socket_trace.bpf.c"
FILES_RW = ROOT / "kernel" / "files_rw.bpf.c"
SOCKET_C = ROOT / "user" / "socket.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        print(message)
        sys.exit(1)


socket_trace_text = SOCKET_TRACE.read_text()
files_rw_text = FILES_RW.read_text()
socket_c_text = SOCKET_C.read_text()

reasm_idx = socket_trace_text.find("socket_info_ptr->reasm_bytes = 0;")
finish_idx = socket_trace_text.find("socket_info_ptr->finish_reasm = false;")
allow_idx = socket_trace_text.find("socket_info_ptr->allow_reassembly = true;")

require(reasm_idx != -1, "missing reasm_bytes reset")
require(finish_idx != -1, "missing finish_reasm reset")
require(allow_idx != -1, "missing allow_reassembly enable")
require(
    reasm_idx < finish_idx < allow_idx,
    "reassembly writes must reset bytes, then finish flag, then enable reassembly",
)

require(
    "Received ai_agent limit_size (%u), the final value is set to '%u'\\n"
    in socket_c_text,
    "ai_agent limit log must use unsigned format specifiers",
)

data_submit_start = socket_trace_text.find("__data_submit(")
require(data_submit_start != -1, "missing __data_submit definition")
push_close_start = socket_trace_text.find("__push_close_event(", data_submit_start)
require(push_close_start != -1, "missing __push_close_event definition")
data_submit_text = socket_trace_text[data_submit_start:push_close_start]

require(
    "__u64 pid_tgid = bpf_get_current_pid_tgid();" in data_submit_text,
    "__data_submit must define pid_tgid before EXTENDED_AI_AGENT_FILE_IO branch uses it",
)

push_close_end = socket_trace_text.find("\n}\n\n#ifdef SUPPORTS_KPROBE_ONLY", push_close_start)
require(push_close_end != -1, "missing __push_close_event end")
push_close_text = socket_trace_text[push_close_start:push_close_end]

require(
    "__u32 buf_len = v_buff->len;" in push_close_text,
    "__push_close_event must copy v_buff->len into a local bounded variable for old verifier",
)
require(
    "Linux 4.19 verifier cannot always infer the range of v_buff->len" in push_close_text,
    "__push_close_event must document why the local bounded length is required",
)
require(
    "buf_len &= (sizeof(*v_buff) - 1);" in push_close_text,
    "__push_close_event must mask local buffer length before map_value pointer arithmetic",
)
require(
    "(struct __socket_data *)(v_buff->data + buf_len)" in push_close_text,
    "__push_close_event must use bounded buf_len for map_value pointer arithmetic",
)

enter_close_start = socket_trace_text.find("TP_SYSCALL_PROG(enter_close)")
require(enter_close_start != -1, "missing enter_close definition")
enter_close_end = socket_trace_text.find("\n}\n\n//int __sys_socket", enter_close_start)
require(enter_close_end != -1, "missing enter_close end")
enter_close_text = socket_trace_text[enter_close_start:enter_close_end]

delete_idx = enter_close_text.find("delete_socket_info(conn_key, socket_info_ptr);")
push_idx = enter_close_text.find("__push_close_event(")
require(delete_idx != -1, "enter_close must delete socket_info")
require(push_idx != -1, "enter_close must push close event")
require(delete_idx < push_idx, "enter_close should delete socket_info before pushing close event")
for field in ("uid", "seq", "l7_proto", "source"):
    require(
        f"close_{field}" in enter_close_text,
        f"enter_close must snapshot close_{field} before deleting socket_info",
    )
require(
    "delete_socket_info(conn_key, socket_info_ptr);\n\t__push_close_event(id, close_uid, close_seq,"
    in enter_close_text,
    "enter_close must push close events with verifier-friendly local snapshots",
)

trace_io_start = files_rw_text.find("trace_io_event_common(")
require(trace_io_start != -1, "missing trace_io_event_common definition")
trace_io_end = files_rw_text.find("\n}\n\n/*\n * File read/write-related", trace_io_start)
require(trace_io_end != -1, "missing trace_io_event_common end")
trace_io_text = files_rw_text[trace_io_start:trace_io_end]

require(
    "EXTENDED_AI_AGENT_FILE_IO_FULL" in files_rw_text,
    "AI Agent file I/O extensions must have a 5.2+/kfunc-only guard for old 4096-insn kernels",
)
require(
    "#ifdef EXTENDED_AI_AGENT_FILE_IO\n" not in trace_io_text,
    "trace_io_event_common must not compile AI Agent file I/O extensions into common BPF",
)
require(
    "#ifdef EXTENDED_AI_AGENT_FILE_IO_FULL\n\tint __ai_agent" in trace_io_text,
    "AI Agent io_event bypass must be guarded by EXTENDED_AI_AGENT_FILE_IO_FULL",
)
require(
    "#ifdef EXTENDED_AI_AGENT_FILE_IO_FULL\n\tbuffer->access_permission =\n"
    "\t    ai_agent_get_access_permission" in trace_io_text,
    "AI Agent access_permission extraction must be guarded by EXTENDED_AI_AGENT_FILE_IO_FULL",
)

print("[OK]")
