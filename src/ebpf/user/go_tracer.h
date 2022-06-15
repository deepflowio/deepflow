#ifndef _BPF_GO_TRACER_H_
#define _BPF_GO_TRACER_H_
#include "symbol.h"
// 获取go ELF版本信息
bool fetch_go_elf_version(const char *path, struct version_info *go_ver);
int uprobe_syms_collect_for_go(struct trace_probes_conf *conf);
#endif
