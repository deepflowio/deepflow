#ifndef _BPF_GO_TRACER_H_
#define _BPF_GO_TRACER_H_
#include "symbol.h"
#include "list_head.h"

#include "../kernel/include/socket_trace_common.h"

struct data_members {
	const char *structure;
	const char *field_name;
	enum offsets_index idx;
	int default_offset;
};

// Pid correspond to offsets.
struct proc_offsets {
	struct list_head list;
	int pid;
	char *path;
	unsigned long long starttime;	// The time the process started after system boot.
	struct member_offsets offs;
	bool has_updated;		// if update eBPF map ?
};

// For process execute/exit events.
struct process_event {
	struct list_head list;          // list add to proc_events_head
	struct bpf_tracer *tracer;      // link to struct bpf_tracer
	uint8_t type;                   // EVENT_TYPE_PROC_EXEC or EVENT_TYPE_PROC_EXIT
	char *path;                     // Full path "/proc/<pid>/root/..."
	int pid;                        // Process ID
	uint32_t expire_time;           // Expiration Date, the number of seconds since the system started.
};

bool is_go_process(int pid);
bool fetch_go_elf_version(const char *path, struct version_info *go_ver);
int collect_uprobe_syms_from_procfs(struct tracer_probes_conf *conf);
void update_go_offsets_to_map(struct bpf_tracer *tracer);
void go_process_exec(int pid);
void go_process_exit(int pid);
void go_process_events_handle(void);
#endif
