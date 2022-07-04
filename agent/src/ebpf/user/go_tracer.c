#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <limits.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>		//PATH_MAX(4096)
#include <arpa/inet.h>
#include <memory.h>
#include "common.h"
#include "bcc/bcc_proc.h"
#include "bcc/bcc_elf.h"
#include "bcc/bcc_syms.h"
#include "log.h"
#include "symbol.h"
#include "tracer.h"
#include "go_tracer.h"
#include "offset.h"
#include "table.h"
#include "symbol.h"
#include "socket.h"

#define MAP_GO_OFFSETS_MAP_NAME	"go_offsets_map"
#define PROCFS_CHECK_PERIOD  60 // 60 seconds
static uint64_t procfs_check_count;

static char build_info_magic[] = "\xff Go buildinf:";

struct list_head proc_offsets_head;	// For pid-offsets correspondence lists.

/* *INDENT-OFF* */
/* ------------- offsets info -------------- */
struct data_members offsets[] = {
	{
		.structure = "runtime.g",
		.field_name = "goid",
		.idx = runtime_g_goid_offset,
		.default_offset = 152,
	},
	{
		.structure = "crypto/tls.Conn",
		.field_name = "conn",
		.idx = crypto_tls_conn_conn_offset,
		.default_offset = 0,
	},
	{
		// on go 1.8 the structure is "net/poll.FD", but the offset 
		// is the same as on go 1.7, so a default offset is given
		.structure = "internal/poll.FD",
		.field_name = "Sysfd",
		.idx = net_poll_fd_sysfd,
		.default_offset = 16,
	},
};

static struct symbol syms[] = {
	{
		.type = GO_UPROBE,
		.symbol = "runtime.casgstatus",
		.probe_func = "runtime_casgstatus",
		.is_probe_ret = false,
	},	
	{
		.type = GO_UPROBE,
		.symbol = "crypto/tls.(*Conn).Write",
		.probe_func = "uprobe_go_tls_write_enter",
		.is_probe_ret = false,
	},	
	{
		.type = GO_UPROBE,
		.symbol = "crypto/tls.(*Conn).Write",
		.probe_func = "uprobe_go_tls_write_exit",
		.is_probe_ret = true,
	},
	{
		.type = GO_UPROBE,
		.symbol = "crypto/tls.(*Conn).Read",
		.probe_func = "uprobe_go_tls_read_enter",
		.is_probe_ret = false,
	},
	{
		.type = GO_UPROBE,
		.symbol = "crypto/tls.(*Conn).Read",
		.probe_func = "uprobe_go_tls_read_exit",
		.is_probe_ret = true,
	},
};
/* *INDENT-ON* */

static char *get_data_buffer_from_addr(Elf * e, uint64_t addr, uint32_t * len)
{
	Elf_Scn *section = NULL;
	static Elf_Data *data = NULL;
	size_t offset;
	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;
		if (!gelf_getshdr(section, &header))
			continue;
		if (header.sh_type == SHT_SYMTAB ||
		    header.sh_type == SHT_DYNSYM ||
		    header.sh_type == SHT_NOBITS)
			continue;
		if (header.sh_addr <= addr
		    && addr < (header.sh_addr + header.sh_size)) {
			data = elf_getdata(section, NULL);
			offset = addr - header.sh_addr;
			*len = header.sh_size - offset;
			return (char *)data->d_buf + offset;
		}
	}

	return NULL;
}

static uint64_t get_addr_from_size_and_mod(int ptr_sz, int end_mode, void *buf)
{
	uint64_t addr;
	if (ptr_sz == 0x8) {
		addr = *(uint64_t *) buf;
		if (end_mode != 0)
			addr =
			    ((uint64_t) ntohl(addr & 0xffffffff)) << 32 |
			    ntohl(addr >> 32);
	} else {
		addr = (uint64_t) (*(uint32_t *) buf);
		if (end_mode != 0)
			addr = (uint64_t) ntohl(*(uint32_t *) buf);
	}
	return addr;
}

bool fetch_go_elf_version(const char *path, struct version_info * go_ver)
{
	bool res = false;
	Elf *e;
	int fd;
	if (openelf(path, &e, &fd) < 0) {
		e = NULL;
		fd = -1;
		goto exit;
	}
	Elf_Data *data = NULL;
	data = get_section_elf_data(e, ".go.buildinfo");
	if (!data)
		goto exit;

	/*
	 * We're focusing on something called .go.buildinfo Part of . Use objdump Check out the details ：
	 * objdump -s -j .go.buildinfo ./bin/kind
	 * Contents of section .go.buildinfo:
	 * c10000 ff20476f 20627569 6c64696e 663a0800  . Go buildinf:..
	 * c10010 70fcc400 00000000 b0fcc400 00000000  p...............
	 * front 14 One byte is magic byte , It has to be for \xff Go buildinf:
	 * The first 15 Bytes represent the size of its pointer , The value here is 0x08, Express 8 Bytes ;
	 * The first 16 Bytes are used to determine whether the byte order is big end mode or small end mode , Not 0 For big end
	 */
	char *info = (char *)data->d_buf;
	if (memcmp(info, build_info_magic, strlen(build_info_magic)))
		goto exit;

	/**
	 * go 1.18+
	 * Contents of section .go.buildinfo:
	 * 575000 ff20476f 20627569 6c64696e 663a0802  . Go buildinf:..
	 * 575010 00000000 00000000 00000000 00000000  ................
	 * 575020 08676f31 2e31382e 33d40530 77af0c92  .go1.18.3..0w...
	 */
	char *buf;
	int num;
	static const int go_version_offset = 0x21;
	if (data->d_size > go_version_offset){
		buf = info + go_version_offset;
		num = sscanf(buf, "go%d.%d", &go_ver->major, &go_ver->minor);
		go_ver->revision = 0;
		if (num == 2) {
			res = true;
			goto exit;
		}
	}

	int ptr_sz = info[14];
	int end_mode = info[15];	// 0 small end mode, Not 0 For big end

	// The 17 beginning of a byte, We get address here. Set value base on the size of its pointer and end mode.
	uint64_t read_ptr =
	    get_addr_from_size_and_mod(ptr_sz, end_mode, (void *)&info[16]);

	uint32_t len = 0;
	buf = get_data_buffer_from_addr(e, read_ptr, &len);
	if (buf == NULL || len <= 0)
		goto exit;

	// Go Version information contents address
	read_ptr =
	    get_addr_from_size_and_mod(ptr_sz, end_mode, (void *)&buf[0]);
	buf = get_data_buffer_from_addr(e, read_ptr, &len);
	if (buf == NULL || len <= 0)
		goto exit;

	num = sscanf(buf, "go%d.%d", &go_ver->major, &go_ver->minor);
	go_ver->revision = 0;
	if (num != 2)
		ebpf_warning("sscanf() go version failed. num = %d\n", num);
	else
		res = true;

exit:
	if (e)
		elf_end(e);
	if (fd >= 0)
		close(fd);

	return res;

}

static struct proc_offsets *find_offset_by_pid(int pid)
{
	struct proc_offsets *p_off;
	list_for_each_entry(p_off, &proc_offsets_head, list) {
		if (p_off->pid == pid)
			return p_off;
	}

	return NULL;
}

static struct proc_offsets *alloc_offset_by_pid(void)
{
	struct proc_offsets *offs;
	offs = calloc(1, sizeof(struct proc_offsets));
	if (offs == NULL) {
		ebpf_warning
		    ("calloc() size:sizeof(struct proc_offsets) error.\n");
		return NULL;
	}

	return offs;
}

static int resolve_bin_file(const char *path, int pid,
			    struct version_info *go_ver,
			    struct tracer_probes_conf *conf)
{
	int ret = ETR_OK;
	struct symbol *sym;
	struct symbol_uprobe *probe_sym;
	struct data_members *off;
	int syms_count = 0;

	for (int i = 0; i < NELEMS(syms); i++) {
		sym = &syms[i];
		probe_sym = resolve_and_gen_uprobe_symbol(path, sym, 0, pid);
		if (probe_sym == NULL) {
			continue;
		}

		bool is_new_offset = false;
		struct proc_offsets *p_offs = find_offset_by_pid(pid);
		if (p_offs == NULL) {
			p_offs = alloc_offset_by_pid();
			if (p_offs == NULL)
				goto faild;
			is_new_offset = true;
		}

		// resolve all offsets.
		for (int k = 0; k < NELEMS(offsets); k++) {
			off = &offsets[k];
			int offset =
			    struct_member_offset_analyze(probe_sym->binary_path,
							 off->structure,
							 off->field_name);
			if (offset == ETR_INVAL)
				offset = off->default_offset;

			p_offs->offs.data[off->idx] = offset;

			p_offs->offs.version =
			    GO_VERSION(go_ver->major, go_ver->minor,
				       go_ver->revision);
			p_offs->pid = pid;
			p_offs->path = strdup(probe_sym->binary_path);
			if (p_offs->path == NULL) {
				free(p_offs);
				goto faild;
			}
		}

		p_offs->has_updated = false;

		if (is_new_offset)
			list_add_tail(&p_offs->list, &proc_offsets_head);

		probe_sym->ver = *go_ver;

		if (probe_sym->isret) {
			size_t addr;
			int j;
			struct symbol_uprobe *sub_probe_sym;
			for (j = 0; j < probe_sym->rets_count; j++) {
				addr = probe_sym->rets[j];
				sub_probe_sym =
				    malloc(sizeof(struct symbol_uprobe));
				if (sub_probe_sym == NULL) {
					ebpf_warning("malloc() error.\n");
					ret = ETR_NOMEM;
					goto faild;
				}

				if ((ret =
				     copy_uprobe_symbol(probe_sym,
							sub_probe_sym))
				    != ETR_OK) {
					free((void *)sub_probe_sym);
					goto faild;
				}

				sub_probe_sym->entry = addr;
				sub_probe_sym->isret = false;
				add_uprobe_symbol(pid, sub_probe_sym, conf);
			}
		} else
			add_uprobe_symbol(pid, probe_sym, conf);

		ebpf_info
		    ("Uprobe [%s] pid:%d go%d.%d.%d entry:0x%lx size:%ld symname:%s probe_func:%s rets_count:%d\n",
		     probe_sym->binary_path, probe_sym->pid,
		     probe_sym->ver.major, probe_sym->ver.minor,
		     probe_sym->ver.revision, probe_sym->entry, probe_sym->size,
		     probe_sym->name, probe_sym->probe_func,
		     probe_sym->rets_count);

		if (probe_sym->isret)
			free_uprobe_symbol(probe_sym, conf);

		syms_count++;
	}

	if (syms_count == 0) {
		ret = ETR_NOSYMBOL;
		ebpf_warning("Go process pid %d [path: %s] (version: go%d.%d). Not find any symbols!\n",
			     pid, path, go_ver->major, go_ver->minor);
	}

	return ret;

faild:
	if (probe_sym->isret)
		free_uprobe_symbol(probe_sym, conf);

	return ret;
}

static int proc_parse_and_register(int pid, struct tracer_probes_conf *conf)
{
	char *path = get_elf_path_by_pid(pid);
	if (path == NULL)
		return ETR_NOTEXIST;

	struct version_info go_version;
	memset(&go_version, 0, sizeof(go_version));
	if (fetch_go_elf_version(path, &go_version)) {
		resolve_bin_file(path, pid, &go_version, conf);
	} else {
		free((void *)path);
		return ETR_NOTGOELF;
	}

	free((void *)path);
	return ETR_OK;
}

// pid is process or thread ?
static bool is_process(int pid)
{
	char file[PATH_MAX], buff[4096];
	int fd;
	int read_tgid = -1, read_pid = -1;

	snprintf(file, sizeof(file), "/proc/%d/status", pid);
	if (access(file, F_OK))
		return false;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return false;

	read(fd, buff, sizeof(buff));
	close(fd);

	char *p = strstr(buff, "Tgid:");
	sscanf(p, "Tgid:\t%d", &read_tgid);

	p = strstr(buff, "Pid:");
	sscanf(p, "Pid:\t%d", &read_pid);

	if (read_tgid == -1 || read_pid == -1)
		return false;

	if (read_tgid != -1 && read_pid != -1 && read_tgid == read_pid)
		return true;

	return false;
}

/**
 * collect_uprobe_syms_from_procfs -- Find all golang binary executables from Procfs,
 * 				      parse and register uprobe symbols.
 *
 * @tps Where probe was registered.
 * @return ETR_OK if ok, else an error
 */
int collect_uprobe_syms_from_procfs(struct tracer_probes_conf *conf)
{
	struct dirent *entry = NULL;
	DIR *fddir = NULL;

	INIT_LIST_HEAD(&proc_offsets_head);

	fddir = opendir("/proc/");
	if (fddir == NULL) {
		ebpf_warning("Failed to open %s.\n");
		return ETR_PROC_FAIL;
	}

	int pid;
	while ((entry = readdir(fddir)) != NULL) {
		pid = atoi(entry->d_name);
		if (entry->d_type == DT_DIR && pid > 1 && is_process(pid))
			proc_parse_and_register(pid, conf);
	}

	closedir(fddir);
	return ETR_OK;
}

static bool pid_exist_in_procfs(int pid, unsigned long long starttime)
{
	struct dirent *entry = NULL;
	DIR *fddir = NULL;
	fddir = opendir("/proc/");
	if (fddir == NULL) {
		ebpf_warning("Failed to open %s.\n");
		return false;
	}

	int read_pid;
	unsigned long long stime;
	while ((entry = readdir(fddir)) != NULL) {
		read_pid = atoi(entry->d_name);
		if (entry->d_type == DT_DIR && pid > 1) {
			stime = get_process_starttime(pid);
			if (stime > 0 && starttime == stime && read_pid == pid) {
				closedir(fddir);
				return true;
			}
		}
	}

	closedir(fddir);
	return false;
}

static bool probe_exist_in_procfs(struct probe *p)
{
	struct symbol_uprobe *sym_uprobe;
	sym_uprobe = p->private_data;
	return pid_exist_in_procfs(sym_uprobe->pid, sym_uprobe->starttime);
}

static bool pid_exist_in_probes(struct bpf_tracer *tracer, int pid,
				unsigned long long starttime)
{
	struct probe *p;
	struct symbol_uprobe *sym;
	list_for_each_entry(p, &tracer->probes_head, list) {
		if (!(p->type == UPROBE && p->private_data != NULL))
			continue;
		sym = p->private_data;
		if (sym->pid == pid && sym->starttime == starttime)
			return true;
	}

	return false;
}

/*
 * Clear all probes, if probe->pid == pid
 */
static void clear_probes_by_pid(struct bpf_tracer *tracer, int pid,
				struct tracer_probes_conf *conf)
{
	struct probe *probe;
	struct list_head *p, *n;
	struct symbol_uprobe *sym_uprobe;

	list_for_each_safe(p, n, &tracer->probes_head) {
		probe = container_of(p, struct probe, list);
		if (!(probe->type == UPROBE && probe->private_data != NULL))
			continue;
		sym_uprobe = probe->private_data;
		if (sym_uprobe->pid == pid) {
			if (probe_detach(probe) != 0)
				ebpf_warning
				    ("path:%s, symbol name:%s probe_detach() faild.\n",
				     sym_uprobe->binary_path, sym_uprobe->name);
			else
				ebpf_info
				    ("%s path:%s, symbol name:%s probe_detach() success.\n",
				     __func__, sym_uprobe->binary_path,
				     sym_uprobe->name);

			free_probe_from_tracer(probe);
			free_uprobe_symbol(sym_uprobe, conf);
		}
	}
}

/**
 * period_update_procfs - Managing all golang processes
 * @tracer: struct bpf_tracer
 */
static int period_update_procfs(void)
{
	procfs_check_count++;
	if (procfs_check_count % PROCFS_CHECK_PERIOD != 0)
		return ETR_INVAL;

	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return ETR_INVAL;

	if (tracer->state != TRACER_RUNNING)
		return ETR_INVAL;

	struct tracer_probes_conf *conf = tracer->tps;
	struct probe *probe;
	struct list_head *p, *n;
	unsigned long long stime;	// The time the process started after system boot.

	/*
	 * Walk through the existing probes to find the probes that 
	 * have been installed but the process does not exist.
	 */
	list_for_each_safe(p, n, &tracer->probes_head) {
		probe = container_of(p, struct probe, list);
		if (!(probe->type == UPROBE && probe->private_data != NULL))
			continue;

		if (probe_exist_in_procfs(probe))
			continue;

		/*
		 *  The process does not exist.
		 *  1. detach probe
		 *  2. remove probe from tracer->probes_head list and free probe
		 *  3. free symbol
		 */
		struct symbol_uprobe *sym_uprobe = probe->private_data;
		if (probe_detach(probe) != 0)
			ebpf_warning
			    ("path:%s, symbol name:%s address:0x%x probe_detach() faild.\n",
			     sym_uprobe->binary_path, sym_uprobe->name,
			     sym_uprobe->entry);
		else
			ebpf_info
			    ("%s path:%s, symbol name:%s address:0x%x probe_detach() success.\n",
			     __func__, sym_uprobe->binary_path,
			     sym_uprobe->name, sym_uprobe->entry);

		free_probe_from_tracer(probe);
		free_uprobe_symbol(sym_uprobe, conf);
	}

	struct dirent *entry = NULL;
	DIR *fddir = NULL;
	int pid;

	fddir = opendir("/proc/");
	if (fddir == NULL) {
		ebpf_warning("Failed opendir() /proc/ errno %d\n", errno);
		return ETR_PROC_FAIL;
	}

	/*
	 * Walk through procfs to find the process that not in
	 * tracer->probes_head list.
	 */
	while ((entry = readdir(fddir)) != NULL) {
		pid = atoi(entry->d_name);
		if (entry->d_type == DT_DIR && pid > 1 && is_process(pid)) {
			stime = get_process_starttime(pid);
			if (pid_exist_in_probes(tracer, pid, stime))
				continue;
			// clear probe->pid == pid
			clear_probes_by_pid(tracer, pid, conf);
			// Resolve bin file and add new uprobe symbol
			proc_parse_and_register(pid, conf);
		}
	}

	closedir(fddir);
	tracer_uprobes_update(tracer);
	tracer_hooks_process(tracer, HOOK_ATTACH);
	update_go_offsets_to_map(tracer);
	return ETR_OK;
}

void update_go_offsets_to_map(struct bpf_tracer *tracer)
{
	struct proc_offsets *p_off;
	char buff[4096];
	struct member_offsets *offs;
	int len, i;

	list_for_each_entry(p_off, &proc_offsets_head, list) {
		if (p_off->has_updated)
			continue;
		offs = &p_off->offs;
		uint64_t pid = p_off->pid;
		if (!bpf_table_set_value
		    (tracer, MAP_GO_OFFSETS_MAP_NAME, pid, (void *)offs))
			continue;
		len =
		    snprintf(buff, sizeof(buff), "go%d.%d.%d offsets:",
			     offs->version >> 16, ((offs->version >> 8) & 0xff),
			     (uint8_t) offs->version);
		for (i = 0; i < offsets_num; i++) {
			len +=
			    snprintf(buff + len, sizeof(buff) - len, "%d:%d ",
				     i, offs->data[i]);
		}

		p_off->has_updated = true;
		ebpf_info("Udpate map %s, key(pid):%d, value:%s",
			  MAP_GO_OFFSETS_MAP_NAME, p_off->pid, buff);
	}
}

int go_probes_manage_init(void)
{
	int ret;
	if ((ret =
	     register_period_event_op("go-probes-check",
				      period_update_procfs))) {
		ebpf_warning
		    ("go-probes-check register_period_event_op() faild.");
		return ret;
	}

	return ETR_OK;
}
