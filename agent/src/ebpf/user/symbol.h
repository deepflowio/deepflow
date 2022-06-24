#ifndef _BPF_SYMBOL_H_
#define _BPF_SYMBOL_H_
#include <stdint.h>

#define FUNC_RET_MAX 32

enum uprobe_type {
	GO_UPROBE = 0,
	C_UPROBE,
	OTHER_UPROBE
};

struct symbol {
	enum uprobe_type type;
	const char *symbol;
	const char *probe_func;
	bool is_probe_ret;
};

struct version_info {
	int major;
	int minor;
	int revision;
};

struct load_addr_t {
	uint64_t target_addr;
	uint64_t binary_addr;
};

struct symbol_uprobe {
	struct list_head list;
	enum uprobe_type type;
	int pid;
	const char *name;	//symbol名字
	const char *binary_path;	//so或目标可执行文件全路径
	const char *probe_func;
	size_t entry;		//入口地址
	uint64_t size;		//函数块大小
	struct version_info ver;
	size_t rets[FUNC_RET_MAX];
	int rets_count;		// 返回数量 可用来判断是否attch rets
	bool isret;
};

struct symbol_kprobe {
	bool isret;		// only use kprobe
	char *symbol;		// only use uprobe
	char *func;
};

struct symbol_tracepoint {
	char *name;
};

void free_uprobe_symbol(struct symbol_uprobe *u_sym);
int copy_uprobe_symbol(struct symbol_uprobe *src, struct symbol_uprobe *dst);
char *get_elf_path_by_pid(int pid);
struct symbol_uprobe *resolve_and_gen_uprobe_symbol(const char *bin_file,
						    struct symbol *sym,
						    const uint64_t addr,
						    int pid);
#endif
