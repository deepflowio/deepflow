/* 
User space for lua_profile BPF program.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/uio.h>
#include <linux/perf_event.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "profile.h"
#include "lua_stacks_helper.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include <linux/types.h> 
#include "profile.skel.h"   
#include "lj_offsets_registry.h"
#include "../../../crates/trace-utils/include/trace_utils.h" 

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

/* This structure combines key_t and count which should be sorted together */
struct key_ext_t
{
	struct profile_key_t k;
	__u64 v;
};

static struct lua_ofs active_lua_offsets;
static bool have_lua_offsets = false;
static struct lj_ofs active_lj_offsets;
static bool have_lj_offsets = false;

#define LUA_CHUNK_READ_MAX 4096

bool exiting = false;
struct lua_stack_map *lua_bt_map = NULL;

// ---- simplified runner config (env + docs + opts) ----

static struct env {
    pid_t pid;                   // target PID
    bool  folded;                // folded output (for flame graphs)
    bool  lua_user_stacks_only;  // show only Lua/C/builtin decoded frames
    bool  disable_lua_user_trace;// force-disable Lua decoding
    int   stack_storage_size;    // stackmap max entries
    int   stack_depth_limit;     // Lua frame-walk bound (verifier friendly)
    int   perf_max_stack_depth;  // perf's user stack capture depth
    bool  verbose;               // libbpf debug logs
} env = {
    .pid = -1,
    .folded = true,
    .lua_user_stacks_only = false,
    .disable_lua_user_trace = false,
    .stack_storage_size = 32768,
    .stack_depth_limit = 15,
    .perf_max_stack_depth = 127,
    .verbose = false,
};


#define warn(...) fprintf(stderr, __VA_ARGS__)
#define UPROBE_SIZE 3
#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
#define SAMPLE_HZ 99

const char *argp_program_version = "profile 0.1";
const char *argp_program_bug_address =
    "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Profile user-space CPU stacks with LuaJIT frame decoding.\n"
    "\n"
    "USAGE: profile [OPTIONS]\n"
    "EXAMPLES:\n"
    "    profile -p 1234          # profile PID 1234 (folded by default)\n"
    "    profile -p 1234 -f       # explicit folded output\n"
    "    profile -p 1234 --lua-user-stacks-only\n"
    "                             # print only Lua/C/builtin decoded frames\n";

#define OPT_STACK_STORAGE_SIZE     1   /* --stack-storage-size */
#define OPT_STACK_DEPTH_LIMIT      2   /* --stack-depth-limit */
#define OPT_PERF_MAX_STACK_DEPTH   3   /* --perf-max-stack-depth */
#define OPT_LUA_USER_STACK_ONLY    4   /* --lua-user-stacks-only */
#define OPT_DISABLE_LUA_USER_TRACE 5   /* --disable-lua-user-trace */

static const struct argp_option opts[] = {
    {"pid", 'p', "PID", 0, "profile this PID only"},
    {"folded", 'f', 0, 0, "folded output (one line per stack)"},
    {"lua-user-stacks-only", OPT_LUA_USER_STACK_ONLY, 0, 0,
        "show only Lua-decoded frames (no generic user frames)"},
    {"disable-lua-user-trace", OPT_DISABLE_LUA_USER_TRACE, 0, 0,
        "disable Lua frame decoding (fallback to generic user symbols)"},
    {"stack-storage-size", OPT_STACK_STORAGE_SIZE, "N", 0,
        "max unique stacks stored (default 32768)"},
    {"stack-depth-limit", OPT_STACK_DEPTH_LIMIT, "N", 0,
        "limit for Lua frame-walk depth (default 15)"},
    {"perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH, "N", 0,
        "limit for user stack capture depth (default 127)"},
    {"verbose", 'v', 0, 0, "verbose libbpf logs"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show help"},
    {}
};



static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    case 'v':
        env.verbose = true;
        break;
    case 'p':
        errno = 0;
        env.pid = strtol(arg, NULL, 10);
        if (errno || env.pid <= 0) {
            fprintf(stderr, "invalid PID: %s\n", arg);
            argp_usage(state);
        }
        break;
    case OPT_STACK_STORAGE_SIZE:
        errno = 0;
        env.stack_storage_size = strtol(arg, NULL, 10);
        if (errno || env.stack_storage_size <= 0) {
            fprintf(stderr, "invalid stack storage size: %s\n", arg);
            argp_usage(state);
        }
        break;
    case OPT_STACK_DEPTH_LIMIT:
        errno = 0;
        env.stack_depth_limit = strtol(arg, NULL, 10);
        if (errno || env.stack_depth_limit <= 0) {
            fprintf(stderr, "invalid stack depth limit: %s\n", arg);
            argp_usage(state);
        }
        break;
    case OPT_PERF_MAX_STACK_DEPTH:
        errno = 0;
        env.perf_max_stack_depth = strtol(arg, NULL, 10);
        if (errno || env.perf_max_stack_depth <= 0) {
            fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
            argp_usage(state);
        }
        break;
    case OPT_LUA_USER_STACK_ONLY:
        env.lua_user_stacks_only = true;
        break;
    case OPT_DISABLE_LUA_USER_TRACE:
        env.disable_lua_user_trace = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}


static int nr_cpus;

static int open_and_attach_perf_event(struct bpf_program *prog,
									  struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_freq = SAMPLE_HZ,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++)
	{


		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0)
		{
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
					strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i])
		{
			fprintf(stderr, "failed to attach perf event on cpu: "
							"%d\n",
					i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int stack_id_err(int stack_id)
{
	return (stack_id < 0) && (stack_id != -EFAULT);
}

static int read_target_mem(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    if (!addr || !buf || !len)
        return -EINVAL;

    struct iovec local = {
        .iov_base = buf,
        .iov_len = len,
    };
    struct iovec remote = {
        .iov_base = (void *)addr,
        .iov_len = len,
    };

    ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (got < 0)
        return -errno;
    if ((size_t)got != len)
        return -EIO;
    return 0;
}

static bool decode_lua_chunkname(pid_t pid, uintptr_t proto_addr, char *dst, size_t dst_sz)
{
    if (!have_lua_offsets || !dst || dst_sz < 2)
        return false;

    uintptr_t ts_ptr = 0;
    if (read_target_mem(pid, proto_addr + active_lua_offsets.off_Proto_source, &ts_ptr, sizeof(ts_ptr)) != 0 ||
        ts_ptr == 0)
        return false;

    size_t max_copy = dst_sz - 1;
    if (max_copy == 0)
        return false;

    uint32_t len = 0;
    bool have_len = active_lua_offsets.off_TString_len != 0;
    if (have_len) {
        if (read_target_mem(pid, ts_ptr + active_lua_offsets.off_TString_len, &len, sizeof(len)) != 0)
            return false;
        if (len > LUA_CHUNK_READ_MAX)
            len = LUA_CHUNK_READ_MAX;
    } else {
        len = max_copy;
    }

    if (len > max_copy)
        len = max_copy;

    if (len && read_target_mem(pid, ts_ptr + active_lua_offsets.sizeof_TString, dst, len) != 0)
        return false;

    dst[len] = '\0';

    return len > 0 || have_len;
}

static __u32 decode_lua_firstline(pid_t pid, uintptr_t proto_addr, __u32 lang_flags)
{
    if ((lang_flags & LANG_LUA) && have_lua_offsets) {
        int line = 0;
        if (read_target_mem(pid, proto_addr + active_lua_offsets.off_Proto_linedefined,
                            &line, sizeof(line)) == 0 && line > 0)
            return (__u32)line;
    }

    if ((lang_flags & LANG_LUAJIT) && have_lj_offsets) {
        int line = 0;
        if (read_target_mem(pid, proto_addr + active_lj_offsets.off_GCproto_firstline,
                            &line, sizeof(line)) == 0 && line > 0)
            return (__u32)line;
    }

    return 0;
}

static bool decode_luajit_chunkname(pid_t pid, uintptr_t proto_addr, char *dst, size_t dst_sz)
{
    if (!have_lj_offsets || !dst || dst_sz < 2)
        return false;

    uint64_t raw_ref = 0;
    if (read_target_mem(pid, proto_addr + active_lj_offsets.off_GCproto_chunkname, &raw_ref, sizeof(raw_ref)) != 0)
        return false;

    uintptr_t gcs_ptr = 0;
    if (active_lj_offsets.gc64) {
        gcs_ptr = (uintptr_t)(raw_ref & ((1ULL << 47) - 1));
    } else {
        gcs_ptr = (uintptr_t)(uint32_t)raw_ref;
    }

    if (gcs_ptr == 0)
        return false;

    uint32_t len = 0;
    if (read_target_mem(pid, gcs_ptr + active_lj_offsets.off_GCstr_len, &len, sizeof(len)) != 0)
        return false;

    size_t max_copy = dst_sz - 1;
    size_t copy_len = len;
    if (copy_len > LUA_CHUNK_READ_MAX)
        copy_len = LUA_CHUNK_READ_MAX;
    if (copy_len > max_copy)
        copy_len = max_copy;

    if (copy_len && read_target_mem(pid, gcs_ptr + active_lj_offsets.off_GCstr_data, dst, copy_len) != 0)
        return false;

    dst[copy_len] = '\0';
    return copy_len > 0 || len == 0;
}

static bool decode_chunkname(pid_t pid, uintptr_t proto_addr, __u32 lang_flags, char *dst, size_t dst_sz)
{
    if (!proto_addr)
        return false;

    if ((lang_flags & LANG_LUAJIT) && decode_luajit_chunkname(pid, proto_addr, dst, dst_sz))
        return true;

    if ((lang_flags & LANG_LUA) && decode_lua_chunkname(pid, proto_addr, dst, dst_sz))
        return true;

    return false;
}


static void resolve_and_print_sample(struct ksyms *ksyms,
                                     struct syms_cache *syms_cache,
                                     int stack_map_fd,
                                     int intp_stack_map_fd,
                                     const struct stack_trace_key_t *rec)
{
    // buffers for IPs
    unsigned long kip[PERF_MAX_STACK_DEPTH + 1] = {0}; // +1 if you ever prepend extra ip
    unsigned long uip[PERF_MAX_STACK_DEPTH]     = {0};
    struct lua_stack_t intp_stack               = {0};
    unsigned int nr_kip = 0, nr_uip = 0, nr_iip = 0;

    const struct syms *us = NULL;
    const struct ksym  *ks = NULL;

    // USER IPs
    if (rec->userstack >= 0) {
        if (bpf_map_lookup_elem(stack_map_fd, &rec->userstack, uip) == 0) {
            while (nr_uip < PERF_MAX_STACK_DEPTH && uip[nr_uip])
                nr_uip++;
            us = syms_cache__get_syms(syms_cache, rec->tgid);
        }
    }

    // KERNEL IPs
    if (rec->kernstack >= 0) {
        if (bpf_map_lookup_elem(stack_map_fd, &rec->kernstack, kip) == 0) {
            while (nr_kip < PERF_MAX_STACK_DEPTH && kip[nr_kip])
                nr_kip++;
        }
    }

    // INTERPRETER (Lua/LuaJIT) packed frames (if any)
    if (rec->intpstack >= 0 && intp_stack_map_fd >= 0) {
        if (bpf_map_lookup_elem(intp_stack_map_fd, &rec->intpstack, &intp_stack) == 0) {
            nr_iip = intp_stack.len;
            if (nr_iip > INTP_MAX_STACK_DEPTH)
                nr_iip = INTP_MAX_STACK_DEPTH;
        } else {
            fprintf(stderr, "[interp] lookup intp_stack_map id %d failed: %s\n",
                    rec->intpstack, strerror(errno));
        }
    }

    // Print header
    printf("=== sample tgid=%u tid=%u comm=%s flags=0x%x ===\n",
           rec->tgid, rec->tid, rec->comm, rec->flags);

    // Kernel
    if (stack_id_err(rec->kernstack))
        printf("  [Missed Kernel Stack] (%d)\n", rec->kernstack);
    else
        for (unsigned j = 0, idx = 0; j < nr_kip; j++) {
            ks = ksyms__map_addr(ksyms, kip[j]);
            if (ks)
                printf("  K #%02u 0x%016lx %s+0x%lx\n", idx++, kip[j], ks->name, kip[j]-ks->addr);
            else
                printf("  K #%02u 0x%016lx [unknown]\n", idx++, kip[j]);
        }

    if (nr_kip && (nr_uip || nr_iip)) printf("  --\n");

    // User (native)
    if (stack_id_err(rec->userstack) && nr_iip == 0)
        printf("  [Missed User Stack] (%d)\n", rec->userstack);
    else {
        unsigned idx = 0;
        for (unsigned j = 0; j < nr_uip; j++) {
            const struct sym *usym = us ? syms__map_addr(us, uip[j]) : NULL;
            if (usym)
                printf("  U #%02u 0x%016lx %s+0x%lx\n", idx++, uip[j], usym->name, usym->offset);
            else
                printf("  U #%02u 0x%016lx [unknown]\n", idx++, uip[j]);
        }

        // Interpreter frames
        for (unsigned j = 0; j < nr_iip; j++) {
            const struct lua_frame_t *frame = &intp_stack.frames[j];
            __u64 enc = frame->tag;
            __u64 addr = frame->addr;
            __u64 tag = enc & TAG_MASK;
            if (tag == TAG_LUA) {
                __u32 line = decode_lua_firstline((pid_t)rec->tgid, (uintptr_t)addr, rec->flags);
                bool has_line = line != 0;
                char chunk[128] = {0};
                bool have_chunk = decode_chunkname((pid_t)rec->tgid, (uintptr_t)addr,
                                                   rec->flags, chunk, sizeof(chunk));
                printf("  I #%02u 0x%016lx ", j, (unsigned long)addr);
                if (have_chunk && has_line)
                    printf("L:%s:%u\n", chunk, line);
                else if (have_chunk)
                    printf("L:%s:?\n", chunk);
                else if (has_line)
                    printf("L:line=%u\n", line);
                else
                    printf("L:line=?\n");
            } else if (tag == TAG_CFUNC) {
                unsigned long encoded_addr = (unsigned long)(enc & ~TAG_MASK);
                unsigned long show = encoded_addr ? encoded_addr : (unsigned long)addr;
                const struct sym *cs = us ? syms__map_addr(us, show) : NULL;
                printf("  I #%02u 0x%016lx ", j, show);
                if (cs)
                    printf("C:%s\n", cs->name);
                else
                    printf("C:0x%016lx\n", show);
            } else if (tag == TAG_FFUNC) {
                __u64 ffid = enc & ~TAG_MASK;
                printf("  I #%02u 0x%016lx builtin#%llu\n", j, (unsigned long)addr, (unsigned long long)ffid);
            } else {
                printf("  I #%02u 0x%016lx [unknown]\n", j, (unsigned long)addr);
            }
        }
    }

    puts("");
}

static void handle_lua_stack_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	int err;
	const struct lua_stack_event *e = data;
	struct tm *tm;
	char ts[16];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	err = insert_lua_stack_map(lua_bt_map, e);
	if (err)
		fprintf(stderr, "failed to insert lua stack map\n");
}

static void handle_lua_stack_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}


struct handler_ctx {
    struct ksyms *ksyms;
    struct syms_cache *syms_cache;
    int stack_map_fd;
    int intp_stack_map_fd; // set to -1 if you don't have this map yet
};

static void handle_sample(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct handler_ctx *h = ctx;
    if (data_sz < sizeof(struct stack_trace_key_t))
        return;

    const struct stack_trace_key_t *rec = data;

    resolve_and_print_sample(
        h->ksyms,
        h->syms_cache,
        h->stack_map_fd,
        h->intp_stack_map_fd,
        rec
    );
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "lost %llu samples on CPU %d\n",
            (unsigned long long)lost_cnt, cpu);
}

static int attach_lua_uprobes(struct profile_bpf *obj, struct bpf_link *links[], char lua_path[])
{
	off_t func_off = get_elf_func_offset(lua_path, "lua_resume");
	if (func_off < 0)
	{
        warn("could not find lua_resume in %s\n", lua_path);
		return -1;
	}
	links[0] = bpf_program__attach_uprobe(obj->progs.handle_entry_lua, false,
										  -1, lua_path, func_off);
	if (!links[0])
	{
		warn("failed to attach lua_resume: %d\n", -errno);
		return -1;
    }

    func_off = get_elf_func_offset(lua_path, "lua_pcall");
	if (func_off < 0)
	{
        warn("could not find lua_pcall in %s\n", lua_path);
		return -1;
	}
	links[1] = bpf_program__attach_uprobe(obj->progs.handle_entry_lua, false,
		-1, lua_path, func_off);
	if (!links[1])
	{
		warn("failed to attach lua_pcall: %d\n", -errno);
		return -1;
    }

    func_off = get_elf_func_offset(lua_path, "lua_yield");
	if (func_off < 0)
	{
        warn("could not find lua_yield in %s\n", lua_path);
		return -1;
	}
	links[2] = bpf_program__attach_uprobe(obj->progs.handle_entry_lua_cancel, false,
			-1, lua_path, func_off);
	if (!links[2])
	{
		warn("failed to attach lua_yield: %d\n", -errno);
		return -1;
	}
    return 0;
}


int main(int argc, char **argv)
{
    static const struct argp argp = {
        .options = opts,
        .parser  = parse_arg,
        .doc     = argp_program_doc,
    };

    struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
    struct bpf_link *lua_cpu_links[MAX_CPU_NR] = {};
    struct bpf_link *luajit_cpu_links[MAX_CPU_NR] = {};
    struct bpf_link *uprobe_links[UPROBE_SIZE] = {};
    struct profile_bpf *obj = NULL;
    struct perf_buffer *pb = NULL;
    int err = 0;
    LuaJitDetectionResult detection;
    const char *method = NULL;
    const char *version = NULL;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus <= 0 || nr_cpus > MAX_CPU_NR) {
        fprintf(stderr, "invalid cpu count (%d)\n", nr_cpus);
        return 1;
    }


    obj = profile_bpf__open();
    if (!obj) { fprintf(stderr, "failed to open BPF object\n"); return 1; }
    
    char lua_path[128];
    if (env.pid) {
        // First check if this is a Lua process using Rust helper
		if (!lua_is_process(env.pid))
		{
            fprintf(stderr, "Process %d does not appear to be a Lua/LuaJIT process\n", env.pid);
            return -1;
        }

        // Get the Lua library path using Rust helper
        if (lua_get_lib_path(env.pid, lua_path, sizeof(lua_path)) < 0) {
            fprintf(stderr, "failed to get Lua lib path for pid %d\n", env.pid);
            return -1;
        }

        printf("Found Lua library: %s\n", lua_path);

        detection = luajit_detect_offsets(env.pid, lua_path);
        method = (const char *)detection.detection_method;
        version = (const char *)detection.version;
        printf("Lua detection (PID %d):\n", env.pid);
        printf("Version: %s\n", version ? version : "<unknown>");
        printf("  Method: %s\n", method ? method : "<unknown>");
    } else {
        printf("No PID specified, terminated\n");
        return 1;
    }


	// ---- user-only defaults pushed to BPF rodata ----
    obj->rodata->targ_pid           = env.pid;
    obj->rodata->targ_tid           = -1;
    obj->rodata->targ_ns_dev        = 0;
    obj->rodata->targ_ns_ino        = 0;
    obj->rodata->stack_depth_limit  = env.stack_depth_limit;
    obj->rodata->include_idle       = false;

    // stackmap sizing
    bpf_map__set_value_size(obj->maps.stack_map,
                            env.perf_max_stack_depth * sizeof(unsigned long));
    bpf_map__set_max_entries(obj->maps.stack_map, env.stack_storage_size);

    err = profile_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF programs. "
                        "If verifier says 'program too large', try --stack-depth-limit\n");
        goto cleanup;
    }


	__u32 lang = 0;
	// 1) Set language flags
	if (method && strstr(method, "Pure Lua") != NULL) {
		lang = LANG_LUA;
		fprintf(stderr, "Pure Lua detected\n");
	} else {
		lang = LANG_LUAJIT;
		fprintf(stderr, "LuaJIT detected\n");
	}
	int lang_fd = bpf_map__fd(obj->maps.lang_flags_map);
	if (lang_fd < 0) { fprintf(stderr, "no lang_flags_map\n"); goto cleanup; }
	if (bpf_map_update_elem(lang_fd, &env.pid, &lang, BPF_ANY)) {
		perror("update lang_flags_map");
		goto cleanup;
	}

	// 2) Choose offsets id
	__u32 off_id = 0;
	int lua_off_fd = bpf_map__fd(obj->maps.lua_offsets_map);
	int lj_off_fd  = bpf_map__fd(obj->maps.luajit_offsets_map);

	have_lua_offsets = false;
	have_lj_offsets = false;
	if (lang == LANG_LUA) {
		const struct {
			const char *ver;
			__u32 off_id;
			struct lua_ofs ofs;
		} lua_profiles[] = {
			{"5.1", 1, LUA_51_AARCH64},
			{"5.2", 2, LUA_52_AARCH64},
			{"5.3", 3, LUA_53_AARCH64},
			{"5.4", 4, LUA_54_AARCH64},
		};
		for (size_t i = 0; i < sizeof(lua_profiles)/sizeof(lua_profiles[0]); i++) {
			if (version && strcmp(version, lua_profiles[i].ver) == 0) {
				off_id = lua_profiles[i].off_id;
				if (bpf_map_update_elem(lua_off_fd, &off_id, &lua_profiles[i].ofs, BPF_ANY)) {
					perror("update lua_offsets_map");
					goto cleanup;
				}
				active_lua_offsets = lua_profiles[i].ofs;
				have_lua_offsets = true;
				break;
			}
		}
		if (!have_lua_offsets)
			warn("unsupported Lua version %s; Lua chunk names will be omitted\n",
			     version ? version : "(unknown)");
	} else { // LANG_LUAJIT
		off_id = 5;
		struct lj_ofs lj21 = LJ_AARCH64_21_FR2_GC64;
		if (bpf_map_update_elem(lj_off_fd, &off_id, &lj21, BPF_ANY)) {
			perror("update luajit_offsets_map");
			goto cleanup;
		}
		active_lj_offsets = lj21;
		have_lj_offsets = true;
	}

	// 3) Tell BPF which offsets_id
	int uw_fd = bpf_map__fd(obj->maps.lua_unwind_info_map);
	struct lua_unwind_info_t uw = {
		.offsets_id = off_id,
		.state_address = 0, // reserved for future Lua_State* address
	};
	if (bpf_map_update_elem(uw_fd, &env.pid, &uw, BPF_ANY)) {
		perror("update lua_unwind_info_map");
		goto cleanup;
	}


	ksyms = ksyms__load();
	if (!ksyms)
	{
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

    syms_cache = syms_cache__new(0);
    if (!syms_cache) { fprintf(stderr, "failed to create syms_cache\n"); goto cleanup; }

    err = attach_lua_uprobes(obj, uprobe_links, lua_path);
	if (err < 0)
	{
		// cannot found lua lib, so skip lua uprobe
		env.disable_lua_user_trace = true;
	}

    lua_bt_map = init_lua_stack_map();
    if (!lua_bt_map) { err = -1; goto cleanup; }

	int stack_map_fd = bpf_map__fd(obj->maps.stack_map);
	int intp_stack_map_fd = bpf_map__fd(obj->maps.intp_stack_map);

	struct handler_ctx hctx = {
		.ksyms = ksyms,
		.syms_cache = syms_cache,
		.stack_map_fd = stack_map_fd,
		.intp_stack_map_fd = intp_stack_map_fd,
	};

	pb = perf_buffer__new(
			bpf_map__fd(obj->maps.events),
			PERF_BUFFER_PAGES,
			handle_sample,          // <- our new sample handler
			handle_lost,            // <- lost handler
			&hctx,                  // <- ctx passed to handlers
			NULL);
	if (!pb) {
		err = -errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

    if ((lang & LANG_LUA) && open_and_attach_perf_event(obj->progs.do_perf_event_lua, lua_cpu_links) < 0)
        goto cleanup;

    if ((lang & LANG_LUAJIT) && open_and_attach_perf_event(obj->progs.do_perf_event_luajit, luajit_cpu_links) < 0)
        goto cleanup;

    signal(SIGINT, sig_handler);

    // main loop: just poll lua perf events until Ctrl-C
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            warn("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        err = 0;
    }

    // print aggregated folded stacks (user-only, merged with Lua if available)
    // print_map(ksyms, syms_cache, obj);

cleanup:
    for (int i = 0; i < nr_cpus; i++) {
        bpf_link__destroy(lua_cpu_links[i]);
        bpf_link__destroy(luajit_cpu_links[i]);
    }
    for (int i = 0; i < UPROBE_SIZE; i++)
        bpf_link__destroy(uprobe_links[i]);
    perf_buffer__free(pb);
    profile_bpf__destroy(obj);
    syms_cache__free(syms_cache);
    return err != 0;
}
