/*
 * Copyright (c) 2024 Yunshan Networks
 */

#ifndef DF_CPU_BALANCER_H
#define DF_CPU_BALANCER_H


#define MAX_PATH_LEN 256
#define MAX_NIC_NAME_LEN 64
#define MAX_OUTPUT_LEN 512

// Structure to hold NIC information
struct cpu_balancer_nic {
        char name[MAX_NIC_NAME_LEN];    // Network Interface Card (NIC) name
        char pci_device_address[MAX_PATH_LEN];  // PCI device address
        char driver[MAX_PATH_LEN];      // Driver name
        int rx_channels;        // Number of NIC rx channels
        int tx_channels;        // Number of NIC tx channels
        size_t rx_ring_size;    // Receive ring size
        size_t tx_ring_size;    // Transmit ring size
        int promisc;            // The flag that indicates promiscuous mode in network card configuration. 
        int numa_node;
};

int set_cpu_balancer_nics(const char *nic_list);
int cpu_balancer_start(void);
int cpu_balancer_destroy(void);

#endif /* DF_CPU_BALANCER_H */
