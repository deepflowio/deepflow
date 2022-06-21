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

static char build_info_magic[] = "\xff Go buildinf:";
static int num_procs;

static struct symbol probe_syms[] = {
	/*-----  grpc client & server -------*/
	{
		// grpc Clinet & Server request headers,call submit_headers
		.symbol = "grpc/internal/transport.(*loopyWriter).writeHeader",
		.probe_func = "uprobe/loopy_writer_write_header",
		.is_probe_ret = false,
	},
	{
		// grpc Clinet response headers,call probe_http2_operate_headers -> submit_headers
		.symbol = "grpc/internal/transport.(*http2Client).operateHeaders",
		.probe_func = "uprobe/http2_client_operate_headers",
		.is_probe_ret = false,
	},
	{
		// grpc Server response headers,call probe_http2_operate_headers -> submit_headers
		.symbol = "grpc/internal/transport.(*http2Server).operateHeaders",
		.probe_func = "uprobe/http2_server_operate_headers",
		.is_probe_ret = false,
	},

	/*-------- http2 client --------------*/
	{
		// Request headers,call submit_header
		.symbol = "x/net/http2.(*ClientConn).writeHeader",
		.probe_func = "uprobe/http2_client_conn_writeHeader",
		.is_probe_ret = false,
	},
	{
		// Confirm request headers last one,call submit_header
		.symbol = "x/net/http2.(*ClientConn).writeHeaders",
		.probe_func = "uprobe/http2_client_conn_writeHeaders",
		.is_probe_ret = false,
	},
	{
		// Response headers, call submit_headers
		.symbol = "x/net/http2.(*clientConnReadLoop).handleResponse",
		.probe_func = "uprobe/http2_clientConnReadLoop_handleResponse",
		.is_probe_ret = false,
	},

	/*-------- http2 server --------------*/
	{
		// Request headers, call submit_headers
		.symbol = "x/net/http2.(*serverConn).processHeaders",
		.probe_func = "uprobe/http2_serverConn_processHeaders",
		.is_probe_ret = false,
	},
	{
		// Response headers, call direct_submit_header
		.symbol = "x/net/http2.(*serverConn).writeHeaders",
		.probe_func = "uprobe/http2_serverConn_writeHeaders",
		.is_probe_ret = false,
	},
};
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

	int ptr_sz = info[14];
	int end_mode = info[15];	// 0 small end mode, Not 0 For big end

	// The 17 beginning of a byte, We get address here. Set value base on the size of its pointer and end mode.
	uint64_t read_ptr =
	    get_addr_from_size_and_mod(ptr_sz, end_mode, (void *)&info[16]);

	uint32_t len = 0;
	char *buf = get_data_buffer_from_addr(e, read_ptr, &len);
	if (buf == NULL || len <= 0)
		goto exit;

	// Go Version information contents address
	read_ptr =
	    get_addr_from_size_and_mod(ptr_sz, end_mode, (void *)&buf[0]);
	buf = get_data_buffer_from_addr(e, read_ptr, &len);
	if (buf == NULL || len <= 0)
		goto exit;

	int num =
	    sscanf(buf, "go%d.%d.%d", &go_ver->major, &go_ver->minor,
		   &go_ver->revision);
	if (num != 3)
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

static int resolve_bin_file(const char *path, int pid,
			    struct version_info *go_ver,
			    struct trace_probes_conf *conf)
{
	struct symbol *sym;
	struct uprobe_symbol *probe_sym;

	for (int i = 0; i < NELEMS(probe_syms); i++) {
		sym = &probe_syms[i];
		probe_sym = resolve_and_gen_uprobe_symbol(path, sym, 0, pid);
		if (probe_sym == NULL) {
			continue;
		}
		probe_sym->ver = *go_ver;
		list_add_tail(&probe_sym->list, &conf->uprobe_syms_head);
		ebpf_info
		    ("Uprobe [%s] pid:%d go%d.%d.%d entry:0x%lx size:%ld symname:%s probe_func:%s rets_count:%d\n",
		     path, probe_sym->pid, probe_sym->ver.major,
		     probe_sym->ver.minor, probe_sym->ver.revision,
		     probe_sym->entry, probe_sym->size, probe_sym->name,
		     probe_sym->probe_func, probe_sym->rets_count);

		conf->uprobe_count++;
	}

	return ETR_OK;
}

static int proc_parse_and_register(int pid, struct trace_probes_conf *conf)
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
 * collect_uprobe_syms_from_procfs -- 从procfs寻找所有的golang exe,
 * 				 解析并注册uprobe symbols。
 * @tps: 用于记录所有probe的结构地址，uprobe symbols会登记到上面。
 * @return: 返回ETR_OK成功，否则失败。
 */
int collect_uprobe_syms_from_procfs(struct trace_probes_conf *conf)
{
	log_to_stdout = true;
	struct dirent *entry = NULL;
	DIR *fddir = NULL;

	fddir = opendir("/proc/");
	if (fddir == NULL) {
		ebpf_warning("Failed to open %s.\n");
		return ETR_PROC_FAIL;
	}

	int pid;
	while ((entry = readdir(fddir)) != NULL) {
		pid = atoi(entry->d_name);
		if (entry->d_type == DT_DIR && pid > 1)
			if (proc_parse_and_register(pid, conf) == 0)
				num_procs++;
	}

	closedir(fddir);
	return ETR_OK;
}
