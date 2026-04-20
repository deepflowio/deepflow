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

print("[OK]")
