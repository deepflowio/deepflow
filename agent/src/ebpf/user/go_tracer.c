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

#define MAP_GO_OFFSETS_MAP_NAME	"go_offsets_map"

static char build_info_magic[] = "\xff Go buildinf:";
static int num_procs;

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
	/*-------- http2 server --------------*/
	{
		// Request headers, call submit_headers
		.type = GO_UPROBE,
		.symbol = "x/net/http2.(*serverConn).processHeaders",
		.probe_func = "uprobe_http2_serverConn_processHeaders",
		.is_probe_ret = false,
	},
	{
		// Response headers, call direct_submit_header
		.type = GO_UPROBE,
		.symbol = "x/net/http2.(*serverConn).writeHeaders",
		.probe_func = "uprobe_http2_serverConn_writeHeaders",
		.is_probe_ret = false,
	},
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

static struct proc_offsets *alloc_offset_by_pid(int pid)
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

	for (int i = 0; i < NELEMS(syms); i++) {
		sym = &syms[i];
		probe_sym = resolve_and_gen_uprobe_symbol(path, sym, 0, pid);
		if (probe_sym == NULL) {
			continue;
		}

		bool is_new_offset = false;
		struct proc_offsets *p_offs = find_offset_by_pid(pid);
		if (p_offs == NULL) {
			p_offs = alloc_offset_by_pid(pid);
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
				list_add_tail(&sub_probe_sym->list,
					      &conf->uprobe_syms_head);
				conf->uprobe_count++;
			}
		} else {
			list_add_tail(&probe_sym->list,
				      &conf->uprobe_syms_head);
			conf->uprobe_count++;
		}

		ebpf_info
		    ("Uprobe [%s] pid:%d go%d.%d.%d entry:0x%lx size:%ld symname:%s probe_func:%s rets_count:%d\n",
		     probe_sym->binary_path, probe_sym->pid, probe_sym->ver.major,
		     probe_sym->ver.minor, probe_sym->ver.revision,
		     probe_sym->entry, probe_sym->size, probe_sym->name,
		     probe_sym->probe_func, probe_sym->rets_count);

		if (probe_sym->isret)
			free_uprobe_symbol(probe_sym);
	}

	return ret;

faild:
	if (probe_sym->isret)
		free_uprobe_symbol(probe_sym);

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
	} else
		return ETR_NOTGOELF;

	free((void *)path);
	return ETR_OK;
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
	log_to_stdout = true;
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
		if (entry->d_type == DT_DIR && pid > 1)
			if (proc_parse_and_register(pid, conf) == ETR_OK)
				num_procs++;
	}

	closedir(fddir);
	return ETR_OK;
}

void update_go_offsets_to_map(struct bpf_tracer *tracer)
{
	struct proc_offsets *p_off;
	char buff[4096];
	struct member_offsets *offs;
	int len, i;

	list_for_each_entry(p_off, &proc_offsets_head, list) {
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

		ebpf_info("Udpate map %s, key(pid):%d, value:%s",
			  MAP_GO_OFFSETS_MAP_NAME, p_off->pid, buff);
	}
}
