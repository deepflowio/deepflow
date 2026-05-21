#!/usr/bin/env python3

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOCKET_TRACE = ROOT / "kernel" / "socket_trace.bpf.c"
FILES_RW = ROOT / "kernel" / "files_rw.bpf.c"
SOCKET_C = ROOT / "user" / "socket.c"
LOAD_C = ROOT / "user" / "load.c"
PROBE_C = ROOT / "user" / "probe.c"
TRACER_H = ROOT / "user" / "tracer.h"
TRACER_C = ROOT / "user" / "tracer.c"
WORKSPACE_ROOT = ROOT.parents[3]
ENTERPRISE_AGENT = WORKSPACE_ROOT / "deepflow-core" / "agent"
ENTERPRISE_BPF = ENTERPRISE_AGENT / "src" / "ebpf" / "user" / "extended" / "bpf"
ENTERPRISE_SUPPORT = ENTERPRISE_AGENT / "scripts" / "support_extended_observability"
ENTERPRISE_FEATURE_TOP = ENTERPRISE_AGENT / "src" / "ebpf" / "user" / "extended" / "feature.top.mk"


def require(condition: bool, message: str) -> None:
    if not condition:
        print(message)
        sys.exit(1)


def read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


socket_trace_text = read_source(SOCKET_TRACE)
files_rw_text = read_source(FILES_RW)
socket_c_text = read_source(SOCKET_C)
load_text = read_source(LOAD_C)
probe_text = read_source(PROBE_C)
tracer_h_text = read_source(TRACER_H)
tracer_c_text = read_source(TRACER_C)

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
require(
    'tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_execve");'
    not in socket_c_text
    and 'tps_set_symbol(tps, "tracepoint/syscalls/sys_enter_execveat");'
    not in socket_c_text,
    "AI Agent exec argv enforcement must not attach sys_enter_execve tracepoints in the large socket-trace program",
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
require(
    re.search(
        r"#ifdef USE_SOCKET_TRACE_SYSCALL_TAIL_CALLS\s+"
        r"if \(extra->source == DATA_SOURCE_SYSCALL\) \{\s+"
        r"struct tail_calls_context \*context =\s+"
        r"\(struct tail_calls_context \*\)v->data;.*?"
        r"return SUBMIT_OK;\s+\}\s+#endif\s+#ifdef USE_SOCKET_TRACE_INLINE_OUTPUT",
        data_submit_text,
        re.S,
    ),
    "__data_submit must keep 5.2_plus syscall traffic on the tail-call output path before inline output fallback",
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

require(
    "#define USE_SOCKET_TRACE_SYSCALL_TAIL_CALLS 1" in socket_trace_text
    and "defined(LINUX_VER_5_2_PLUS)" in socket_trace_text
    and "defined(EXTENDED_AI_AGENT_FILE_IO)" in socket_trace_text,
    "5.2_plus socket-trace must re-enable syscall tail-call splitting when AI Agent governance is compiled in",
)

for helper_name in (
    "process_syscall_data",
    "process_syscall_data_vecs",
):
    helper_idx = socket_trace_text.find(helper_name)
    require(helper_idx != -1, f"missing {helper_name}")
    helper_text = socket_trace_text[helper_idx : helper_idx + 2200]
    require(
        "USE_SOCKET_TRACE_SYSCALL_TAIL_CALLS" in helper_text,
        f"{helper_name} must use the syscall tail-call split guard",
    )

require(
    "USE_SOCKET_TRACE_SYSCALL_TAIL_CALLS" in socket_trace_text
    and "extra->source == DATA_SOURCE_SYSCALL" in socket_trace_text,
    "5.2_plus AI Agent tail-call split must be limited to syscall source paths",
)

require('"lsm/"' in load_text, "load.c must recognize lsm/ section prefix")
require(
    "BPF_PROG_TYPE_LSM" in load_text,
    "load.c must map lsm/ programs to BPF_PROG_TYPE_LSM",
)
require(
    "prog_load_name" in load_text
    and "prog->type == BPF_PROG_TYPE_LSM" in load_text
    and '"lsm__%s"' in load_text,
    "load.c must pass lsm__<hook> to BCC so it sets BPF_LSM_MAC and lets libbpf find bpf_lsm_<hook>",
)
require(
    "program__attach_lsm" in probe_text,
    "probe.c must provide an LSM attach helper",
)
require(
    "bpf_raw_tracepoint_open" in probe_text,
    "LSM attach helper must use the raw tracepoint attach syscall path",
)
require(
    "bpf_raw_tracepoint_open(NULL, ebpf_prog->prog_fd)" in probe_text,
    "LSM attach helper must attach by loaded attach_btf_id, not by raw tracepoint hook name",
)
require(
    "struct lsm_prog" in tracer_h_text and "lsms_count" in tracer_h_text,
    "tracer.h must keep LSM program attach state",
)
require(
    "lsm_programs_handle" in tracer_c_text,
    "tracer.c must include LSM programs in the attach lifecycle",
)
require(
    "optional_kprobe_programs_handle" in tracer_c_text,
    "tracer.c must include optional AI Agent kprobe programs in the attach lifecycle",
)
require(
    "new_prog->type == BPF_PROG_TYPE_LSM" in load_text
    and "Skip optional BPF LSM program" in load_text,
    "load.c must keep unsupported BPF LSM programs non-fatal",
)
require(
    "p->prog->prog_fd < 0" in tracer_c_text
    and "skip unloaded lsm program" in tracer_c_text,
    "tracer.c must skip unloaded optional LSM programs during attach",
)

if ENTERPRISE_AGENT.exists():
    exec_enforce_bpf = ENTERPRISE_BPF / "ai_agent_exec_enforce.bpf.c"
    exec_common_bpf = ENTERPRISE_BPF / "ai_agent_exec_common.bpf.h"
    require(
        exec_enforce_bpf.exists(),
        f"missing enterprise AI Agent exec enforcement BPF: {exec_enforce_bpf}",
    )
    require(
        exec_common_bpf.exists(),
        f"missing enterprise AI Agent exec common BPF header: {exec_common_bpf}",
    )
    exec_enforce_text = read_source(exec_enforce_bpf)
    exec_common_text = read_source(exec_common_bpf)
    support_text = read_source(ENTERPRISE_SUPPORT)
    feature_top_text = read_source(ENTERPRISE_FEATURE_TOP)

    require(
        'SEC("lsm/bprm_check_security")' in exec_enforce_text,
        "AI Agent exec enforcement must attach to lsm/bprm_check_security",
    )
    require(
        "BPF_PROG(bpf_lsm_bprm_check_security," in exec_enforce_text,
        "AI Agent exec enforcement BPF function name must match the bpf_lsm_<hook> BTF name for BCC/libbpf lookup",
    )
    require(
        "is_ai_agent_process" in exec_enforce_text
        or "ai_agent_pids" in exec_enforce_text,
        "AI Agent exec enforcement must scope matching to AI Agent processes",
    )
    require(
        "DATA_SOURCE_PROC_BLOCK_EVENT" in exec_common_text,
        "AI Agent exec enforcement must emit proc block events",
    )
    require(
        re.search(r"#define\s+AI_AGENT_EXEC_MAX_RULES\s+256", exec_common_text),
        "AI Agent exec enforcement must expose a 256-record BPF-side exec rule cap",
    )
    require(
        "args ? args->cmdline : exec_path" not in exec_enforce_text,
        "AI Agent exec LSM hook must not use a ternary map_value_or_null cmdline pointer on old verifiers",
    )
    require(
        "MAP_PERARRAY(ai_agent_exec_path_buf" in exec_enforce_text
        and "struct ai_agent_exec_path *path_buf" in exec_enforce_text
        and "path_buf->path" in exec_enforce_text
        and "char exec_path[AI_AGENT_EXEC_PATTERN_LEN]" not in exec_enforce_text,
        "AI Agent exec LSM hook must keep exec_path in a scratch map, not a large stack array with variable-index reads",
    )
    require(
        "TP_SYSCALL_PROG(enter_execve)" not in exec_enforce_text
        and "TP_SYSCALL_PROG(enter_execveat)" not in exec_enforce_text
        and "ai_agent_capture_exec_args" not in exec_enforce_text
        and "argv_match_bits" not in exec_enforce_text,
        "AI Agent exec LSM hook must not depend on sys_enter_execve argv capture",
    )
    require(
        "AI_AGENT_EXEC_MATCH_SUFFIX" in exec_common_text
        and "suffix_hash" in exec_common_text
        and "ai_agent_exec_collect_path_facts" in exec_common_text,
        "AI Agent exec enforcement BPF must support suffix path matching with precomputed hashes",
    )
    require(
        "ai_agent_exec_starts_with" not in exec_enforce_text
        and "ai_agent_exec_ends_with" not in exec_enforce_text
        and "exec_path[exec_idx]" not in exec_enforce_text,
        "AI Agent exec LSM hook must not use dynamic-offset string comparisons on old verifiers",
    )
    require(
        "ai_agent_exec_argv_hashes" not in exec_enforce_text
        and "ai_agent_update_argv_match_bits" not in exec_enforce_text
        and "ai_agent_cmdline_contains" not in exec_enforce_text,
        "AI Agent exec LSM enforcement must stay path-only; argv matching belongs in small kprobe override programs",
    )
    lsm_body = exec_enforce_text[
        exec_enforce_text.find('SEC("lsm/bprm_check_security")') :
    ]
    require(
        "rule->argv_pattern_len != 0" in exec_enforce_text
        and "argv_pattern" not in lsm_body
        and "argv_pattern_hash" not in lsm_body,
        "AI Agent exec LSM hook must ignore argv-qualified rules to avoid blocking path-only false positives",
    )
    require(
        "pattern_hash" in exec_common_text
        and "ai_agent_hash_exec_path" in exec_common_text,
        "AI Agent exec enforcement BPF must keep exact path hashing for low-cost exact matches",
    )
    require(
        "ai_agent_submit_event" in exec_common_text,
        "AI Agent exec enforcement must submit events through the AI Agent pipeline",
    )
    require(
        "cmdline_src_sz" in exec_common_text
        and "cmdline, cmdline_src_sz" in exec_common_text
        and "path_buf->path,\n\t\t\t\t       AI_AGENT_EXEC_PATTERN_LEN" in exec_enforce_text,
        "AI Agent exec block event must copy cmdline using the actual source buffer size",
    )
    require(
        "ai_agent_exec_enforce.bpf.c" in support_text,
        "support_extended_observability must include ai_agent_exec_enforce.bpf.c",
    )
    exec_override_bpf = ENTERPRISE_BPF / "ai_agent_exec_override.bpf.c"
    exec_override_standalone_bpf = ENTERPRISE_BPF / "ai_agent_exec_override_standalone.bpf.c"
    require(
        exec_override_bpf.exists(),
        f"missing enterprise AI Agent exec override BPF: {exec_override_bpf}",
    )
    require(
        exec_override_standalone_bpf.exists(),
        f"missing enterprise standalone AI Agent exec override BPF wrapper: {exec_override_standalone_bpf}",
    )
    exec_override_text = read_source(exec_override_bpf)
    exec_override_standalone_text = read_source(exec_override_standalone_bpf)
    exec_bpf_text = "\n".join((exec_enforce_text, exec_common_text, exec_override_text))
    for forbidden in (
        "argv_contains_any",
        "AI_AGENT_EXEC_MATCH_ARGV_CONTAINS",
        "ARGV_CONTAINS",
        "cmdline_regex",
        "ai_agent_cmdline_contains",
        "cmdline_contains",
    ):
        require(
            forbidden not in exec_bpf_text,
            f"AI Agent exec strong-block BPF must not contain legacy argv/cmdline selector '{forbidden}'",
        )
    require(
        'SEC("kprobe/__x64_sys_execve")' in exec_override_text
        and 'SEC("kprobe/__x64_sys_execveat")' in exec_override_text
        and "bpf_override_return(ctx," in exec_override_text,
        "AI Agent argv-qualified exec enforcement must use small kprobe override programs",
    )
    require(
        re.search(r"#define\s+AI_AGENT_EXEC_OVERRIDE_ARG_LEN\s+64", exec_override_text)
        and "ai_agent_exec_override_read_argv_index" in exec_override_text
        and "rule->argv_index" in exec_override_text
        and "rule->argv_op != AI_AGENT_EXEC_ARGV_OP_EXACT" in exec_override_text
        and "ai_agent_exec_override_arg_matches" in exec_override_text,
        "AI Agent exec override must read only the configured argv index",
    )
    require(
        "ai_agent_exec_override_read_syscall_arg" in exec_override_text
        and "const char *filename = (const char *)PT_REGS_PARM1(ctx);" not in exec_override_text
        and "const char *const *argv = (const char *const *)PT_REGS_PARM2(ctx);" not in exec_override_text
        and "const char *filename = (const char *)PT_REGS_PARM2(ctx);" not in exec_override_text
        and "const char *const *argv = (const char *const *)PT_REGS_PARM3(ctx);" not in exec_override_text,
        "AI Agent exec override must decode syscall-wrapper pt_regs before reading execve filename/argv",
    )
    require(
        "rule->argv_pattern_len == buf->arg_len" in exec_override_text
        and "buf->arg.words[0] == rule->argv_pattern_words[0]" in exec_override_text
        and "buf->arg.words[7] == rule->argv_pattern_words[7]" in exec_override_text
        and "rule->argv_pattern," not in exec_override_text,
        "AI Agent exec override must compare argv by fixed len+word chunks, not by scanning policy argv_pattern from map values",
    )
    require(
        "df_K_ai_agent_exec_override_" in tracer_c_text
        and "df_K_ai_agent_exec_override_" in load_text,
        "tracer/load must treat AI Agent exec override kprobes as optional kprobe override programs",
    )
    require(
        "ai_agent_exec_override.bpf.c" not in support_text
        or 'socket_trace_bpf_path" "#include "../user/extended/bpf/ai_agent_exec_override.bpf.c"' not in support_text,
        "support_extended_observability must not include argv exec override into socket_trace.bpf.c",
    )
    require(
        "AI_AGENT_EXEC_OVERRIDE_ELFS" in feature_top_text
        and "ai_agent_exec_override_standalone.bpf.c" in feature_top_text,
        "enterprise Makefile extension must build argv exec override as a standalone BPF object",
    )
    require(
        "MAP_PERF_EVENT(socket_data" in exec_override_standalone_text
        and "MAP_HASH(ai_agent_pids" in exec_override_standalone_text
        and "ai_agent_submit_event" in exec_override_standalone_text
        and '#include "ai_agent_exec_override.bpf.c"' in exec_override_standalone_text,
        "standalone exec override wrapper must define shared map symbols and include only exec override kprobes",
    )
    require(
        "buf->arg.bytes,\n\t\t\t\t       AI_AGENT_EXEC_OVERRIDE_ARG_LEN" in exec_override_text,
        "AI Agent exec override must emit argv cmdline with the 64-byte argv buffer size, not the 256-byte path size",
    )
    syscall_override_bpf = ENTERPRISE_BPF / "ai_agent_syscall_override.bpf.c"
    require(
        syscall_override_bpf.exists(),
        f"missing enterprise AI Agent syscall override BPF: {syscall_override_bpf}",
    )
    syscall_override_text = read_source(syscall_override_bpf)
    require(
        "bpf_override_return(ctx," in syscall_override_text,
        "AI Agent syscall enforcement must use bpf_override_return for blocking",
    )
    require(
        'SEC("kprobe/__x64_sys_reboot")' in syscall_override_text,
        "AI Agent syscall enforcement must hook direct reboot syscall with kprobe override",
    )
    require(
        "df_K_ai_agent_syscall_override_" in tracer_c_text
        or "optional kprobe: 'kprobe/__x64_sys_reboot'" in tracer_c_text,
        "tracer.c must explicitly attach AI Agent syscall override kprobes",
    )
    require(
        "ai_agent_syscall_override.bpf.c" in support_text,
        "support_extended_observability must include ai_agent_syscall_override.bpf.c",
    )
    require(
        "df_K_ai_agent_syscall_override_" in load_text
        and "Skip optional AI Agent kprobe override program" in load_text,
        "load.c must keep unsupported AI Agent kprobe override programs non-fatal",
    )

print("[OK]")
