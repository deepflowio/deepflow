/*
 * Copyright (c) 2024 Yunshan Networks
 */

#ifndef DF_CPU_BALANCER_H
#define DF_CPU_BALANCER_H

#define MAX_PATH_LEN 256
#define MAX_NIC_NAME_LEN 64
#define MAX_OUTPUT_LEN 512

/**
 * @struct cpu_balancer_nic
 * @brief Structure to hold Network Interface Card (NIC) information for CPU balancing.
 */
struct cpu_balancer_nic {
	char name[MAX_NIC_NAME_LEN];	/**< Network Interface Card (NIC) name. */
	char pci_device_address[MAX_PATH_LEN];
					   /**< PCI device address of the NIC. */
	char driver[MAX_PATH_LEN];	/**< Driver name associated with the NIC. */
	int rx_channels;		/**< Number of NIC receive (RX) channels. */
	int tx_channels;		/**< Number of NIC transmit (TX) channels. */
	size_t rx_ring_size;		/**< Size of the receive ring buffer. */
	size_t tx_ring_size;		/**< Size of the transmit ring buffer. */
	int promisc;			/**< Flag indicating if promiscuous mode is enabled in the NIC configuration. */
	int numa_node;			/**< NUMA node number to which the NIC is associated. */
	char *nic_cpus;			/**< 
                                   * List of CPUs handling network data received by the NIC, 
                                   * triggered by a physical interrupt.
                                   */
	char *xdp_cpus;			/**< 
                                   * List of CPUs used for XDP (eXpress Data Path) processing. 
                                   * Ensures there is no overlap with nic_cpus.
                                   */
};

/**
 * @brief Configure the NICs for the CPU balancer.
 * 
 * This function must be called before `cpu_balancer_start()`.
 * 
 * @param nic_list Names of the network interfaces to be configured for the CPU balancer, e.g., "eth0".
 * @param ring_size The size of the receive ring buffer for the NIC.
 * @param nic_cpus List of CPUs handling network data received by the NIC, e.g., "3,5,7".
 * @param xdp_cpus List of CPUs used for XDP (eXpress Data Path) processing, e.g., "13,15,16,21-31".
 * @return 0 on success, non-zero on failure.
 */
int set_cpu_balancer_nics(const char *nic_list, size_t ring_size,
			  const char *nic_cpus, const char *xdp_cpus);

/**
 * @brief Start the CPU balancer.
 * 
 * This function initializes and activates the CPU balancer for configured NICs.
 * 
 * @return 0 on success, non-zero on failure.
 */
int cpu_balancer_start(void);

/**
 * @brief Destroy the CPU balancer.
 * 
 * Cleans up resources used by the CPU balancer and stops its operation.
 * 
 * @return 0 on success, non-zero on failure.
 */
int cpu_balancer_destroy(void);

#endif /* DF_CPU_BALANCER_H */
