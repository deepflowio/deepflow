/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
#include <bcc/bcc_proc.h>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include "config.h"
#include "log.h"
#include "symbol.h"
#include "tracer.h"
#include "go_tracer.h"
#include "offset.h"
#include "table.h"
#include "symbol.h"
#include "socket.h"
#include "elf.h"

// For process execute/exit events.
struct process_event {
	struct list_head list;          // list add to proc_events_head
	struct bpf_tracer *tracer;      // link to struct bpf_tracer
	uint8_t type;                   // EVENT_TYPE_PROC_EXEC or EVENT_TYPE_PROC_EXIT
	char *path;                     // Full path "/proc/<pid>/root/..."
	int pid;                        // Process ID
	uint32_t expire_time;           // Expiration Date, the number of seconds since the system started.
};

static char build_info_magic[] = "\xff Go buildinf:";
static struct list_head proc_info_head;	// For pid-offsets correspondence lists.
static struct list_head proc_events_head;     // For process execute/exit events list.
static pthread_mutex_t mutex_proc_events_lock;

/* *INDENT-OFF* */
/* ------------- offsets info -------------- */
static struct data_members offsets[] = {
	{
		.structure = "runtime.g",
		.field_name = "goid",
		.idx = OFFSET_IDX_GOID_RUNTIME_G,
		.default_offset = 152,
	},
	{
		.structure = "crypto/tls.Conn",
		.field_name = "conn",
		.idx = OFFSET_IDX_CONN_TLS_CONN,
		.default_offset = 0,
	},
	{
		// on go 1.8 the structure is "net/poll.FD", but the offset 
		// is the same as on go 1.7, so a default offset is given
		.structure = "internal/poll.FD",
		.field_name = "Sysfd",
		.idx = OFFSET_IDX_SYSFD_POLL_FD,
		.default_offset = 16,
	},
	{
		.structure = "net/http.http2serverConn",
		.field_name = "conn",
		.idx = OFFSET_IDX_CONN_HTTP2_SERVER_CONN,
		.default_offset = 16,
	},
	{
		.structure = "net/http.http2ClientConn",
		.field_name = "tconn",
		.idx = OFFSET_IDX_TCONN_HTTP2_CLIENT_CONN,
		.default_offset = 8,
	},
	{
		.structure = "net/http.http2clientConnReadLoop",
		.field_name = "cc",
		.idx = OFFSET_IDX_CC_HTTP2_CLIENT_CONN_READ_LOOP,
		.default_offset = 0,
	},
	{
		.structure = "google.golang.org/grpc/internal/transport.http2Client",
		.field_name = "conn",
		.idx = OFFSET_IDX_CONN_GRPC_HTTP2_CLIENT,
		.default_offset = 64,
	},
	{
		.structure = "google.golang.org/grpc/internal/transport.http2Server",
		.field_name = "conn",
		.idx = OFFSET_IDX_CONN_GRPC_HTTP2_SERVER,
		.default_offset = 32,
	},
	{
		.structure = "google.golang.org/grpc/internal/transport.loopyWriter",
		.field_name = "framer",
		.idx = OFFSET_IDX_FRAMER_GRPC_TRANSPORT_LOOPY_WRITER,
		.default_offset = 40,
	},
	{
		.structure = "google.golang.org/grpc/internal/transport.framer",
		.field_name = "writer",
		.idx = OFFSET_IDX_WRITER_GRPC_TRANSPORT_FRAMER,
		.default_offset = 0,
	},
	{
		.structure = "google.golang.org/grpc/internal/transport.bufWriter",
		.field_name = "conn",
		.idx = OFFSET_IDX_CONN_GRPC_TRANSPORT_BUFWRITER,
		.default_offset = 40,
	},
	{
		.structure = "google.golang.org/grpc/internal/transport.loopyWriter",
		.field_name = "side",
		.idx = OFFSET_IDX_SIDE_GRPC_TRANSPORT_LOOPY_WRITER,
		.default_offset = 0,
	},
	{
		.structure = "net/http.http2MetaHeadersFrame",
		.field_name = "Fields",
		.idx = OFFSET_IDX_FIELDS_HTTP2_META_HEADERS_FRAME,
		.default_offset = 8,
	},
	{
		.structure = "net/http.http2ClientConn",
		.field_name = "nextStreamID",
		.idx = OFFSET_IDX_STREAM_HTTP2_CLIENT_CONN,
		.default_offset = 176,
	},
	{
		.structure = "net/http.http2FrameHeader",
		.field_name = "StreamID",
		.idx = OFFSET_IDX_STREAM_ID_HTTP2_FRAME_HEADER,
		.default_offset = 8,
	}
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
		.symbol = "runtime.newproc1",
		.probe_func = "enter_runtime_newproc1",
		.is_probe_ret = false,
	},
	{
		.type = GO_UPROBE,
		.symbol = "runtime.newproc1",
		.probe_func = "exit_runtime_newproc1",
		.is_probe_ret = true,
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
	// HTTP2，symbols select an interface based on the GO version.
	// http2 server, fetch response headers
	// Send multiple header messages and add an end marker message at the end
	{
		.type = GO_UPROBE,
		.symbol = "net/http.(*http2serverConn).writeHeaders",
		.probe_func = "uprobe_go_http2serverConn_writeHeaders",
		.is_probe_ret = false,
	},
	{
		.type = GO_UPROBE,
		.symbol = "golang.org/x/net/http2.(*serverConn).writeHeaders",
		.probe_func = "uprobe_go_http2serverConn_writeHeaders",
		.is_probe_ret = false,
	},
	// http2 server, fetch request headers
	// Send multiple header messages and add an end marker message at the end
	{
		.type = GO_UPROBE,
		.symbol = "net/http.(*http2serverConn).processHeaders",
		.probe_func = "uprobe_go_http2serverConn_processHeaders",
		.is_probe_ret = false,
	},
	{
		.type = GO_UPROBE,
		.symbol = "golang.org/x/net/http2.(*serverConn).processHeaders",
		.probe_func = "uprobe_go_http2serverConn_processHeaders",
		.is_probe_ret = false,
	},
	// http2 client, fetch response headers
	// Send multiple header messages and add an end marker message at the end
	{
		.type = GO_UPROBE,
		.symbol = "net/http.(*http2clientConnReadLoop).handleResponse",
		.probe_func = "uprobe_go_http2clientConnReadLoop_handleResponse",
		.is_probe_ret = false,
	},
	{
		.type = GO_UPROBE,
		.symbol = "golang.org/x/net/http2.(*clientConnReadLoop).handleResponse",
		.probe_func = "uprobe_go_http2clientConnReadLoop_handleResponse",
		.is_probe_ret = false,
	},
	// http2 client, fetch request headers
	// Send multiple header messages
	{
		.type = GO_UPROBE,
		.symbol = "net/http.(*http2ClientConn).writeHeader",
		.probe_func = "uprobe_go_http2ClientConn_writeHeader",
		.is_probe_ret = false,
	},
	{
		.type = GO_UPROBE,
		.symbol = "golang.org/x/net/http2.(*ClientConn).writeHeader",
		.probe_func = "uprobe_go_http2ClientConn_writeHeader",
		.is_probe_ret = false,
	},
	// http2 client, fetch request headers
	// Send end marker message
	{
		.type = GO_UPROBE,
		.symbol = "net/http.(*http2ClientConn).writeHeaders",
		.probe_func = "uprobe_go_http2ClientConn_writeHeaders",
		.is_probe_ret = false,
	},
	{
		.type = GO_UPROBE,
		.symbol = "golang.org/x/net/http2.(*ClientConn).writeHeaders",
		.probe_func = "uprobe_go_http2ClientConn_writeHeaders",
		.is_probe_ret = false,
	},
	// gRPC
	// grpc client request or server response, distinguish by side
	// Send multiple header messages and add an end marker message at the end
	{
		.type = GO_UPROBE,
		.symbol = "google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader",
		.probe_func = "uprobe_go_loopyWriter_writeHeader",
		.is_probe_ret = false,
	},
	// grpc client fetch response headers
	// Send multiple header messages and add an end marker message at the end
	{
		.type = GO_UPROBE,
		.symbol = "google.golang.org/grpc/internal/transport.(*http2Client).operateHeaders",
		.probe_func = "uprobe_go_http2Client_operateHeaders",
		.is_probe_ret = false,
	},
	// grpc server fetch request headers
	// Send multiple header messages and add an end marker message at the end
	{
		.type = GO_UPROBE,
		.symbol = "google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders",
		.probe_func = "uprobe_go_http2Server_operateHeaders",
		.is_probe_ret = false,
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
	// TODO : Ignore kubernetes, there needs to be a better way.
	if (strstr(path, "root/opt/kube/"))
		return false;

	bool res = false;
	Elf *e;
	int fd;
	if (openelf(path, &e, &fd) < 0) {
		e = NULL;
		fd = -1;
		goto exit;
	}
	Elf_Data *data = NULL;
	data = get_sec_elf_data(e, ".go.buildinfo");
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
	if (data->d_size > go_version_offset) {
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

static struct proc_info *find_proc_info_by_pid(int pid)
{
	struct proc_info *p_info;
	list_for_each_entry(p_info, &proc_info_head, list) {
		if (p_info->pid == pid)
			return p_info;
	}

	return NULL;
}

static struct proc_info *alloc_proc_info_by_pid(void)
{
	struct proc_info *info;
	info = calloc(1, sizeof(struct proc_info));
	if (info == NULL) {
		ebpf_warning
		    ("calloc() size:sizeof(struct proc_info) error.\n");
		return NULL;
	}

	return info;
}

static int resolve_bin_file(const char *path, int pid,
			    struct version_info *go_ver,
			    struct tracer_probes_conf *conf, int *resolve_num)
{
	int ret = ETR_OK;
	struct symbol *sym;
	struct symbol_uprobe *probe_sym = NULL;
	struct data_members *off;
	char *binary_path = NULL;
	int syms_count = 0;

	for (int i = 0; i < NELEMS(syms); i++) {
		sym = &syms[i];
		probe_sym = resolve_and_gen_uprobe_symbol(path, sym, 0, pid);
		if (probe_sym == NULL) {
			continue;
		}

		if (!binary_path){
			binary_path = strdup(probe_sym->binary_path);
			if (binary_path == NULL) {
				goto failed;
			}
		}

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
					goto failed;
				}

				if ((ret = copy_uprobe_symbol(probe_sym,
							      sub_probe_sym)) !=
				    ETR_OK) {
					free((void *)sub_probe_sym);
					goto failed;
				}

				sub_probe_sym->entry = addr;
				sub_probe_sym->isret = false;
				add_uprobe_symbol(pid, sub_probe_sym, conf);
			}
		} else
			add_uprobe_symbol(pid, probe_sym, conf);

		ebpf_info(
			"Uprobe [%s] pid:%d go%d.%d.%d entry:0x%lx size:%ld symname:%s probe_func:%s rets_count:%d\n",
			probe_sym->binary_path, probe_sym->pid,
			probe_sym->ver.major, probe_sym->ver.minor,
			probe_sym->ver.revision, probe_sym->entry,
			probe_sym->size, probe_sym->name, probe_sym->probe_func,
			probe_sym->rets_count);

		if (probe_sym->isret)
			free_uprobe_symbol(probe_sym, NULL);

		syms_count++;
	}

	if (syms_count == 0) {
		ret = ETR_NOSYMBOL;
		ebpf_warning(
			"Go process pid %d [path: %s] (version: go%d.%d). Not find any symbols!"
			" You can try setting the configuration option 'golang-symbol' to see "
			"if it resolves the issue, if the issue persists, please attempt to "
			"resolve it using the Golang executable with symbol table included.\n",
			pid, path, go_ver->major, go_ver->minor);
		goto failed;
	}

	struct proc_info *p_info = NULL;
	if (binary_path){
		bool is_new_info = false;
		p_info = find_proc_info_by_pid(pid);
		if (p_info == NULL) {
			p_info = alloc_proc_info_by_pid();
			if (p_info == NULL)
				goto offset_failed;
			is_new_info = true;
		}

		p_info->info.version = GO_VERSION(go_ver->major, go_ver->minor,
						  go_ver->revision);
		p_info->pid = pid;

		if (p_info->path != NULL) {
			free(p_info->path);
			p_info->path = NULL;
		}

		p_info->path = strdup(binary_path);
		if (p_info->path == NULL) {
			goto offset_failed;
		}
		// resolve all offsets.
		for (int k = 0; k < NELEMS(offsets); k++) {
			off = &offsets[k];
			int offset =
			    struct_member_offset_analyze(binary_path,
							 off->structure,
							 off->field_name);
			if (offset == ETR_INVAL)
				offset = off->default_offset;

			p_info->info.offsets[off->idx] = offset;
		}

		const char *tcp_conn_sym, *tls_conn_sym, *syscall_conn_sym;
		if (p_info->info.version < GO_VERSION(1, 20, 0)) {
			tcp_conn_sym = "go.itab.*net.TCPConn,net.Conn";
			tls_conn_sym = "go.itab.*crypto/tls.Conn,net.Conn";
			syscall_conn_sym =
				"go.itab.*google.golang.org/grpc/internal/credentials.syscallConn,net.Conn";
		} else {
			tcp_conn_sym = "go:itab.*net.TCPConn,net.Conn";
			tls_conn_sym = "go:itab.*crypto/tls.Conn,net.Conn";
			syscall_conn_sym =
				"go:itab.*google.golang.org/grpc/internal/credentials.syscallConn,net.Conn";
		}

		p_info->info.net_TCPConn_itab =
			get_symbol_addr_from_binary(binary_path, tcp_conn_sym);
		if (p_info->info.net_TCPConn_itab == 0)
			ebpf_warning("'%s' does not exist. Since eBPF uprobe relies on it to retrieve "
				     "connection information, if it is empty, eBPF will not retrieve any"
				     " data. This situation may be due to the lack of symbol table in "
				     "the golang executable (confirm by executing 'nm %s'). If it shows "
				     "'no symbols', you can try setting the configuration option "
				     "'golang-symbol' to see if it resolves the issue, if the issue "
				     "persists, please attempt to resolve it using the Golang executable "
				     "with symbol table included.\n", tcp_conn_sym, binary_path);

		p_info->info.crypto_tls_Conn_itab =
			get_symbol_addr_from_binary(binary_path, tls_conn_sym);

		p_info->info.credentials_syscallConn_itab = get_symbol_addr_from_binary(
			binary_path, syscall_conn_sym);

		p_info->has_updated = false;

		if (is_new_info)
			list_add_tail(&p_info->list, &proc_info_head);

		free(binary_path);
		binary_path = NULL;
	}

	*resolve_num = syms_count;
	return ret;

failed:
	*resolve_num = syms_count;
	if (probe_sym && probe_sym->isret) {
		free_uprobe_symbol(probe_sym, NULL);
	}

	if (binary_path) {
		free(binary_path);
	}
	return ret;

offset_failed:
	*resolve_num = syms_count;
	if (p_info != NULL) {
		free(p_info);
	}
	if (binary_path) {
		free(binary_path);
	}

	return ETR_INVAL;
}

static int proc_parse_and_register(int pid, struct tracer_probes_conf *conf)
{
	int syms_count = 0;
	char *path = get_elf_path_by_pid(pid);
	if (path == NULL)
		return syms_count;

	if (!is_feature_matched(FEATURE_UPROBE_GOLANG, path))
		goto out;

	struct version_info go_version;
	memset(&go_version, 0, sizeof(go_version));
	if (fetch_go_elf_version(path, &go_version)) {
		resolve_bin_file(path, pid, &go_version, conf, &syms_count);
	} else {
		free((void *)path);
		return syms_count;
	}

out:
	free((void *)path);
	return syms_count;
}

/*
 * Check if it is the GO program ?
 */
bool is_go_process(int pid)
{
	bool ret = false;
	char *path = get_elf_path_by_pid(pid);
	if (path == NULL)
		return false;
	struct version_info go_version;
	memset(&go_version, 0, sizeof(go_version));
	if (fetch_go_elf_version(path, &go_version))
		ret = true;
	free((void *)path);
	return ret;
}


/**
 * collect_go_uprobe_syms_from_procfs -- Find all golang binary executables from Procfs,
 * 				      parse and register uprobe symbols.
 *
 * @tps Where probe was registered.
 * @return ETR_OK if ok, else an error
 */
int collect_go_uprobe_syms_from_procfs(struct tracer_probes_conf *conf)
{
	struct dirent *entry = NULL;
	DIR *fddir = NULL;

	init_list_head(&proc_events_head);
	init_list_head(&proc_info_head);
	pthread_mutex_init(&mutex_proc_events_lock, NULL);

	if (!is_feature_enabled(FEATURE_UPROBE_GOLANG))
		return ETR_OK;

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

static bool __attribute__ ((unused)) probe_exist_in_procfs(struct probe *p)
{
	struct symbol_uprobe *sym_uprobe;
	sym_uprobe = p->private_data;
	return pid_exist_in_procfs(sym_uprobe->pid, sym_uprobe->starttime);
}

static bool __attribute__ ((unused)) pid_exist_in_probes(struct bpf_tracer *tracer, int pid,
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

static bool __attribute__ ((unused)) pid_exist_in_probes_without_stime(struct bpf_tracer
								       *tracer,
								       int pid)
{
	struct probe *p;
	struct symbol_uprobe *sym;
	list_for_each_entry(p, &tracer->probes_head, list) {
		if (!(p->type == UPROBE && p->private_data != NULL))
			continue;
		sym = p->private_data;
		if (sym->pid == pid)
			return true;
	}

	return false;
}

static struct proc_info *find_proc_info(int pid)
{
	struct proc_info *p_info = NULL;
	list_for_each_entry(p_info, &proc_info_head, list) {
		if (p_info->pid == pid)
			return p_info;
	}

	return NULL;
}

static void free_proc_info(struct proc_info *p_info)
{
	// Free memory occupied by structure members.
	if (p_info->path != NULL) {
		free(p_info->path);
	}

	free(p_info);
}

/*
 * Clear all probes, if probe->pid == pid
 */
static void clear_probes_by_pid(struct bpf_tracer *tracer, int pid,
				struct tracer_probes_conf *conf)
{
	bool info_print = false;
	struct probe *probe;
	struct list_head *p, *n;
	struct symbol_uprobe *sym_uprobe;

	struct proc_info *p_info = find_proc_info(pid);
	if (p_info) {
		list_head_del(&p_info->list);
		free_proc_info(p_info);
	}

	list_for_each_safe(p, n, &tracer->probes_head) {
		probe = container_of(p, struct probe, list);
		if (!(probe->type == UPROBE && probe->private_data != NULL))
			continue;
		sym_uprobe = probe->private_data;

		if (sym_uprobe->type != GO_UPROBE)
			continue;

		if (sym_uprobe->pid == pid) {
			if (probe_detach(probe) != 0) {
				ebpf_warning
				    ("path:%s, symbol name:%s probe_detach() failed.\n",
				     sym_uprobe->binary_path, sym_uprobe->name);
			}

			if (!info_print) {
				ebpf_info("Clear process PID %d\n", pid);
				info_print = true;
			}
				
			free_probe_from_tracer(probe);
		}
	}
}

void update_proc_info_to_map(struct bpf_tracer *tracer)
{
	struct proc_info *p_info;
	char buff[4096];
	struct ebpf_proc_info *info;
	int len, i;

	list_for_each_entry(p_info, &proc_info_head, list) {
		if (p_info->has_updated)
			continue;
		info = &p_info->info;
		int pid = p_info->pid;
		if (!bpf_table_set_value
		    (tracer, MAP_PROC_INFO_MAP_NAME, pid, (void *)info))
			continue;
		len =
		    snprintf(buff, sizeof(buff), "go%d.%d offsets:",
			     info->version >> 16, ((info->version >> 8) & 0xff));
		for (i = 0; i < OFFSET_IDX_MAX; i++) {
			len +=
			    snprintf(buff + len, sizeof(buff) - len, "%d:%d ",
				     i, info->offsets[i]);
		}

		p_info->has_updated = true;
		ebpf_info("Udpate map %s, key(pid):%d, value:%s",
			  MAP_PROC_INFO_MAP_NAME, p_info->pid, buff);
	}
}

static void process_execute_handle(int pid, struct bpf_tracer *tracer)
{
	/*
	 * Probes attach/detach in multithreading
	 * e.g.: In start/stop tracer need process probes in different threads.
	 * Protect the probes operation in multiple threads by use mutex_probes_lock. 
	 */
	pthread_mutex_lock(&tracer->mutex_probes_lock);
	struct tracer_probes_conf *conf = tracer->tps;
	// Clear all probe process id == pid
	clear_probes_by_pid(tracer, pid, conf);
	// Resolve symbols and register uprobe symbols  
	if (proc_parse_and_register(pid, conf) > 0) {
		// Add new probes by symbols 
		tracer_uprobes_update(tracer);
		// Attach probes
		int count = 0;
		if (tracer_hooks_process(tracer, HOOK_ATTACH, &count) == ETR_OK) {
			if (count > 0)
				// Update offsets map
				update_proc_info_to_map(tracer);
		}
	}
	pthread_mutex_unlock(&tracer->mutex_probes_lock);
}

static void process_exit_handle(int pid, struct bpf_tracer *tracer)
{
	// Protect the probes operation in multiple threads, similar to process_execute_handle()
	pthread_mutex_lock(&tracer->mutex_probes_lock);
	struct tracer_probes_conf *conf = tracer->tps;
	clear_probes_by_pid(tracer, pid, conf);
	pthread_mutex_unlock(&tracer->mutex_probes_lock);
}

static void add_event_to_proc_header(struct bpf_tracer *tracer, int pid, uint8_t type)
{
	char *path = get_elf_path_by_pid(pid);
	if (path == NULL) {
		return;
	}

	if (!is_feature_matched(FEATURE_UPROBE_GOLANG, path)) {
		free(path);
		return;
	}

	struct process_event *pe = calloc(1, sizeof(struct process_event));
	if (pe == NULL) {
		free(path);
		ebpf_warning("Without memory.\n");
		return;
	}

	pe->tracer = tracer;
	pe->path = path;
	pe->pid = pid;
	pe->type = type;
	pe->expire_time = get_sys_uptime() + PROC_EVENT_DELAY_HANDLE_DEF; 

	pthread_mutex_lock(&mutex_proc_events_lock);
	list_add_tail(&pe->list, &proc_events_head);
	pthread_mutex_unlock(&mutex_proc_events_lock);	
}

/**
 * go_process_exec - syscalls/sys_exit_execve event process.
 * @pid Process ID 
 */
void go_process_exec(int pid)
{
	struct bpf_tracer *tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return;

	if (tracer->state != TRACER_RUNNING)
		return;

	if (tracer->probes_count > OPEN_FILES_MAX) {
		ebpf_warning("Probes count too many. The maximum is %d\n",
			     OPEN_FILES_MAX);
		return;
	}

	add_event_to_proc_header(tracer, pid, EVENT_TYPE_PROC_EXEC);
}

/**
 * go_process_exit - sched/sched_process_exit event process.
 * @pid Process ID
 */
void go_process_exit(int pid)
{
	struct bpf_tracer *tracer;
	if (!is_feature_enabled(FEATURE_UPROBE_GOLANG))
		return;

	tracer = find_bpf_tracer(SK_TRACER_NAME);
	if (tracer == NULL)
		return;

	if (tracer->state != TRACER_RUNNING)
		return;

	process_exit_handle(pid, tracer);
}

/**
 * go_process_events_handle - process exec/exit events handle, called by process_events_handle_main().
 */
void go_process_events_handle(void)
{
	struct process_event *pe;
	do {
		// Multithreaded safe fetch 'struct process_event'
		pthread_mutex_lock(&mutex_proc_events_lock);
		if (!list_empty(&proc_events_head)) {
			pe = list_first_entry(&proc_events_head,
					      struct process_event, list);
		} else {
			pe = NULL;
		}
		pthread_mutex_unlock(&mutex_proc_events_lock);

		if (pe == NULL)
			break;

		if (get_sys_uptime() >= pe->expire_time) {
			pthread_mutex_lock(&mutex_proc_events_lock);
			list_head_del(&pe->list);
			pthread_mutex_unlock(&mutex_proc_events_lock);

			if (pe->type == EVENT_TYPE_PROC_EXEC) {
				/*
				 * Threads and processes share the code section,
				 * here only processes are concerned.
				 */
				if (is_process(pe->pid)
				    && access(pe->path, F_OK) == 0) {
					process_execute_handle(pe->pid,
							       pe->tracer);
				}
			}

			free(pe->path);
			free(pe);
		} else {
			break;
		}
	} while (true);
}
