/*
 * Copyright (c) 2024 Yunshan Networks
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

#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <linux/version.h>
#include <string.h>
#include "../config.h"
#include "../tracer.h"
#include "../socket.h"
#include "../proc.h"
#include "../utils.h"
#include "../log.h"
#include "../load.h"
#include "cpu_balancer.h"

#include "bpf/cpu_balancer_bpf_bytecode.c"

#define LOG_LB_TAG       "[CPU-LB] "
#define cpulb_info(format,args...) \
  ebpf_info(LOG_LB_TAG format, ## args)

#define cpulb_warning(format,args...) \
  ebpf_warning(LOG_LB_TAG format, ## args)

static char tracer_name[] = "cpu-balancer";
static struct bpf_tracer *g_tracer;
struct cpu_balancer_nic *g_cpu_nics;
static void cpu_balancer_set_probes(struct tracer_probes_conf *tps)
{
	tps_set_symbol(tps, "tracepoint/xdp/xdp_redirect_err");
	tps_set_symbol(tps, "tracepoint/xdp/xdp_redirect_map_err");
	tps_set_symbol(tps, "tracepoint/xdp/xdp_exception");
	tps_set_symbol(tps, "tracepoint/xdp/xdp_cpumap_enqueue");
	tps_set_symbol(tps, "tracepoint/xdp/xdp_cpumap_kthread");
}

void print_cpu_balancer_status(void)
{
	//
}

static inline bool is_invalid_str(char *s)
{
	return !(s != NULL && *s != '\0');
}

int set_cpu_balancer_nics(const char *nic_name, size_t ring_size,
			  const char *nic_cpus, const char *xdp_cpus)
{
	if (is_invalid_str(nic_name)) {
		cpulb_warning("nic_name cannot be empty.\n");
		return -1;
	}

	if (ring_size <= 0) {
		cpulb_warning("ring_size must be greater than 0.\n");
		return -1;
	}

	if (is_invalid_str(nic_cpus)) {
		cpulb_warning("nic_cpus cannot be empty.\n");
		return -1;
	}

	if (is_invalid_str(xdp_cpus)) {
		cpulb_warning("xdp_cpus cannot be empty.\n");
		return -1;
	}

	struct cpu_balancer_nic nic;
	memset(&nic, 0, sizeof(nic));
	snprintf(nic.name, sizeof(nic.name), "%s", nic_name);
	nic.rx_ring_size = ring_size;
	int len = strlen(nic_cpus) + 1;
	nic.nic_cpus = malloc(len);
	if (nic.nic_cpus == NULL) {
		cpulb_warning("malloc() failed.\n");
		return -1;
	}
	snprintf(nic.nic_cpus, len, "%s", nic_cpus);

	len = strlen(xdp_cpus) + 1;
	nic.xdp_cpus = malloc(len);
	if (nic.xdp_cpus == NULL) {
		free(nic.nic_cpus);
		cpulb_warning("malloc() failed.\n");
		return -1;
	}
	snprintf(nic.xdp_cpus, len, "%s", xdp_cpus);

	int ret = VEC_OK;
	vec_add1(g_cpu_nics, nic, ret);
	if (ret != VEC_OK) {
		cpulb_warning("vec add failed.\n");
	}

	return 0;
}

static int release_cpu_balancer(struct bpf_tracer *tracer)
{
	tracer_reader_lock(tracer);

	/* detach perf event */
	tracer_hooks_detach(tracer);

	print_cpu_balancer_status();

	/* release object */
	release_object(tracer->obj);

	tracer_reader_unlock(tracer);

	cpulb_info("release_cpu_balancer().... finish!\n");
	return ETR_OK;
}

static void configure_nic_cpu_balance(struct cpu_balancer_nic *nic)
{
	
	retrieve_pci_info_by_nic(nic->name, nic->pci_device_address,
				 nic->driver, &nic->numa_node);
	get_nic_channels(nic->name, &nic->rx_channels, &nic->tx_channels);
	get_nic_ring_size(nic->name, &nic->rx_ring_size, &nic->tx_ring_size);
	nic->promisc = is_promiscuous_mode(nic->name);
	cpulb_info("Device:%-8s Address:%-14s Driver:%-8s "
		   "Rx-Channels:%-4d Tx-Channels:%-4d RX-Ring-Size:%-5ld TX-Ring-Size:%-5ld "
		   "PROMISC:%-3d NumaNode:%-3d Nic-CPUs:%s XDP-CPUs:%s\n",
		   nic->name, nic->pci_device_address, nic->driver,
		   nic->rx_channels, nic->tx_channels, nic->rx_ring_size,
		   nic->tx_ring_size, nic->promisc, nic->numa_node,
		   nic->nic_cpus, nic->xdp_cpus);

#ifdef PRINT_PCI_INFO
	int ret;
	char pci_info[1024];
	memset(pci_info, 0, sizeof(pci_info));
	char args[128];
	snprintf(args, sizeof(args), "-vmmk -s %s", nic->pci_device_address);
	ret = exec_command("lspci", args, pci_info, sizeof(pci_info));
	if (ret != -1) {
		int i;
		for (i = 0; i < strlen(pci_info); i++) {
			if (pci_info[i] == '\n')
				pci_info[i] = ';';
			if (pci_info[i] == '\t')
				pci_info[i] = ' ';
		}
		cpulb_info("%s\n", pci_info);
	}
#endif
}

int cpu_balancer_start(void)
{
	if (g_tracer != NULL) {
		cpulb_info("The CPU balancer is already running"
			   " and does not need to be started.\n");
		return 0;
	}
	// Linux 4.14: Added support for BPF_MAP_TYPE_CPUMAP, allowing packets
	// to be redirected to specific CPUs. 
	if (check_kernel_version(4, 14) != 0) {
		return -1;
	}

	int nics_count = vec_len(g_cpu_nics);
	if (nics_count <= 0) {
		cpulb_warning("The NICs is not configured, and the CPU"
			      " balancer failed to start.\n");
		return -1;
	}

	cpulb_info("The number of configured network interfaces is %d.\n",
		   nics_count);

	struct cpu_balancer_nic *nic_p;
	vec_foreach(nic_p, g_cpu_nics) {
		configure_nic_cpu_balance(nic_p);
	}

	char bpf_load_buffer_name[NAME_LEN];
	void *bpf_bin_buffer;
	int buffer_sz;
	snprintf(bpf_load_buffer_name, NAME_LEN, "cpu-balancer");
	bpf_bin_buffer = (void *)cpu_balancer_ebpf_data;
	buffer_sz = sizeof(cpu_balancer_ebpf_data);

	struct tracer_probes_conf *tps =
	    malloc(sizeof(struct tracer_probes_conf));
	if (tps == NULL) {
		cpulb_warning("malloc() error.\n");
		return -ENOMEM;
	}

	memset(tps, 0, sizeof(*tps));
	init_list_head(&tps->uprobe_syms_head);
	cpu_balancer_set_probes(tps);

	g_tracer =
	    setup_bpf_tracer(tracer_name, bpf_load_buffer_name,
			     bpf_bin_buffer, buffer_sz, tps,
			     0, release_cpu_balancer, NULL, NULL, NULL, 0);

	if (tracer_bpf_load(g_tracer)) {
		return -EINVAL;
	}

	if (tracer_probes_init(g_tracer))
		return -EINVAL;

	if (tracer_hooks_attach(g_tracer))
		return -EINVAL;

	return 0;
}

int cpu_balancer_destroy(void)
{
	if (g_tracer == NULL) {
		cpulb_info("The CPU balancer is not currently enabled, "
			   "so there is no need to destroy it.\n");
		return 0;
	}

	release_bpf_tracer(tracer_name);
	g_tracer = NULL;

	struct cpu_balancer_nic *nic_p;
	vec_foreach(nic_p, g_cpu_nics) {
		if (nic_p->nic_cpus)
			free(nic_p->nic_cpus);
		if (nic_p->xdp_cpus)
			free(nic_p->xdp_cpus);
	}

	vec_free(g_cpu_nics);
	return 0;
}
