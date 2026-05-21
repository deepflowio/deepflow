#!/usr/bin/env python3

from pathlib import Path
import sys


OSS_EBPF_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = OSS_EBPF_ROOT.parents[3]
TRACER_C = OSS_EBPF_ROOT / "user" / "tracer.c"
UPROBE_BASE = OSS_EBPF_ROOT / "kernel" / "uprobe_base.bpf.c"
AI_AGENT_FILE_OPS = (
    WORKSPACE_ROOT
    / "deepflow-core"
    / "agent"
    / "src"
    / "ebpf"
    / "user"
    / "extended"
    / "bpf"
    / "ai_agent_file_ops.bpf.c"
)
AI_AGENT_PERM_OPS = (
    WORKSPACE_ROOT
    / "deepflow-core"
    / "agent"
    / "src"
    / "ebpf"
    / "user"
    / "extended"
    / "bpf"
    / "ai_agent_perm_ops.bpf.c"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        print(message)
        sys.exit(1)


tracer_text = TRACER_C.read_text()
uprobe_text = UPROBE_BASE.read_text()
file_ops_text = AI_AGENT_FILE_OPS.read_text()
perm_ops_text = AI_AGENT_PERM_OPS.read_text()

require(
    "ai_agent_submit_file_op_event(" in file_ops_text,
    "AI Agent file-op BPF must expose a shared submit helper for TP/KPROBE reuse",
)
for symbol in (
    "KPROG(__x64_sys_openat)",
    "KPROG(__x64_sys_unlink)",
    "KPROG(__x64_sys_unlinkat)",
    "KPROG(__x64_sys_fchmodat)",
    "KPROG(__x64_sys_chmod)",
    "KPROG(__x64_sys_fchownat)",
    "KPROG(__x64_sys_chown)",
):
    require(
        symbol in file_ops_text,
        f"missing AI Agent governance kprobe wrapper: {symbol}",
    )

require(
    "ai_agent_submit_perm_event(" in perm_ops_text,
    "AI Agent perm-op BPF must expose a shared submit helper for TP/KPROBE reuse",
)
for symbol in (
    "KPROG(__x64_sys_setuid)",
    "KPROG(__x64_sys_setgid)",
    "KPROG(__x64_sys_setreuid)",
    "KPROG(__x64_sys_setregid)",
):
    require(
        symbol in perm_ops_text,
        f"missing AI Agent governance kprobe wrapper: {symbol}",
    )

require(
    "governance_tracepoint_fallback_probe_name(" in tracer_text,
    "tracer.c must define governance tracepoint->kprobe fallback mapping",
)
require(
    "governance_tracepoint_fallback_attach(" in tracer_text,
    "tracer.c must attach governance kprobe fallback when tracepoint attach fails",
)
require(
    "tracepoint/sched/sched_process_fork" in tracer_text,
    "tracer.c fallback mapping must cover AI Agent fork governance tracepoint",
)
require(
    "__x64_sys_unlink" in tracer_text
    and '"kprobe/%s"' in tracer_text,
    "tracer.c fallback mapping must resolve unlink governance kprobe target dynamically",
)

require(
    "if (is_kprobe && ret > 0) {" in uprobe_text
    and "ai_agent_on_fork(ctx, (__u32)tgid, (__u32)data.pid);" in uprobe_text,
    "kernel_clone_exit() must propagate AI Agent fork state through shared kretprobe fallback",
)

print("[OK]")
