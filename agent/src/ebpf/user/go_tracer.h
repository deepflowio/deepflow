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
	const char *path;
	unsigned long long starttime;	// The time the process started after system boot.
	struct member_offsets offs;
	bool has_updated;		// if update eBPF map ?
};

bool fetch_go_elf_version(const char *path, struct version_info *go_ver);
int collect_uprobe_syms_from_procfs(struct tracer_probes_conf *conf);
void update_go_offsets_to_map(struct bpf_tracer *tracer);
int go_probes_manage_init(void);
#endif
