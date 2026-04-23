#!/usr/bin/env python3

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOCKET_TRACE = ROOT / "kernel" / "socket_trace.bpf.c"
SOCKET_C = ROOT / "user" / "socket.c"


def require(condition: bool, message: str) -> None:
    if not condition:
        print(message)
        sys.exit(1)


socket_trace_text = SOCKET_TRACE.read_text()
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

print("[OK]")
