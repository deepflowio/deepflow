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
#include "../user/common.h"
#include "../user/bcc/bcc_proc.h"
#include "../user/bcc/bcc_elf.h"
#include "../user/bcc/bcc_syms.h"
#include "../user/log.h"
#include "../user/symbol.h"
#include "../user/tracer.h"
#include "../user/go_tracer.h"

const char *test_go_file =
    "../../../resources/test/ebpf/go-elf";

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

	/*-------- tls --------------*/
	{
		.symbol = "crypto/tls.(*Conn).Write",
		.probe_func = "uprobe/crypto_tls_conn_write",
		.is_probe_ret = true,
	},
	{
		.symbol = "crypto/tls.(*Conn).Read",
		.probe_func = "uprobe/crypto_tls_conn_read",
		.is_probe_ret = false,
	},

	/*-------- runtime.casgstatus --------------*/
	{
		.symbol = "runtime.casgstatus",
		.probe_func = "uprobe/runtime_casgstatus",
		.is_probe_ret = false,
	},
};

int main(void)
{

	struct symbol *sym;
	struct uprobe_symbol *probe_sym;

	struct version_info go_version;
	memset(&go_version, 0, sizeof(go_version));
	printf("Test func fetch_go_elf_version() : ");
	if (!fetch_go_elf_version(test_go_file, &go_version)) {
		printf("[FAIL]\n");
		return -1;
	}
	printf("[OK]\n");

	printf("Test func resolve_and_gen_uprobe_symbol() : ... \n");
	if (resolve_and_gen_uprobe_symbol(NULL, NULL, 0, 0) != NULL) {
		printf("[FAIL]\n");
		return -1;
	}

	int count = 0;
	for (int i = 0; i < NELEMS(probe_syms); i++) {
		sym = &probe_syms[i];
		probe_sym =
		    resolve_and_gen_uprobe_symbol(test_go_file, sym, 0, 0);
		if (probe_sym == NULL) {
			continue;
		}
		count++;
		probe_sym->ver = go_version;
		printf
		    ("... Uprobe [%s] pid:%d\n    go%d.%d.%d\n    entry:0x%lx size:%ld\n"
		     "    symname:%s\n    probe_func:%s\n    rets_count:%d\n",
		     test_go_file, probe_sym->pid, probe_sym->ver.major,
		     probe_sym->ver.minor, probe_sym->ver.revision,
		     probe_sym->entry, probe_sym->size, probe_sym->name,
		     probe_sym->probe_func, probe_sym->rets_count);

	}

	if (count <= 0) {
		printf("[FAIL]\n");
		return -1;
	}

	printf("[OK]\n");

	return 0;
}
