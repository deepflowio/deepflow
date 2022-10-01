# libtrace

This is a library that uses eBPF technology to obtain the tracking data. It can use very simple interface calls to get any valuable data from the kernel or application.

Provides the Rust language interface.

Kernel version support: `Linux 4.14+`

# Protocol Tracing

Deepflow-agent deploys eBPF probes (kprobe/traceponit) on Linux syscalls. When application makes network-related syscalls, deepflow-agent's eBPF probes snoop the data.

The following protocols are currently probed:

- HTTP1
- HTTP2
- DUBBO
- MYSQL
- REDIS
- KAFKA
- MQTT
- DNS

## TLS/SSL Tracing

Currently only for Golang programs and openssl.

Use eBPF user-space probes (uprobes), set up on the Golang application's TLS API.

HTTP1 and HTTP2 protocals data are currently probed on TLS/SSL.

Trace to the Golang program is implemented by the following method:
- All the currently running Golang binary executables are found by traversing Procfs, and then the files are parsed to obtain the Golang version, trace symbol offset address, structure member offsets and other informations.
- Create probes and attach based on the parsed datas.
- Capture process execute/exit events by tracking two tracepoints(`tracepoint/sched/sched_process_fork` and `tracepoint/sched/sched_process_exit`). Update probes based on captured events.

Note: In order to avoid attaching/detaching the golang program repeatedly, it is necessary to confirm that the golang application has been running stably before DeepFlow-agent starts the attach operation. After DeepFlow-agent detects that the golang application is loaded, it delays the attach operation for 120 seconds. Openssl only supports kernel 4.17 and above.

# Tested kernel version

- 4.14.x
  - 4.14.0, 4.14.10, 4.14.11, 4.14.1, 4.14.12, 4.14.13, 4.14.14, 4.14.15, 4.14.2, 4.14.3, 4.14.4, 4.14.5, 4.14.6, 4.14.7, 4.14.8, 4.14.9
- 4.15.x
  - 4.15.0, 4.15.1, 4.15.10, 4.15.11, 4.15.12, 4.15.13, 4.15.14, 4.15.15, 4.15.2, 4.15.3, 4.15.4, 4.15.5, 4.15.6, 4.15.7, 4.15.8, 4.15.9
- 4.16.x
  - 4.16.0, 4.16.1, 4.16.10, 4.16.11, 4.16.12,4.16.13, 4.16.2, 4.16.3, 4.16.4, 4.16.5, 4.16.6, 4.16.7, 4.16.8, 4.16.9
- 4.17.x
  - 4.17.0, 4.17.1, 4.17.10, 4.17.11,4.17.12, 4.17.13, 4.17.14, 4.17.2, 4.17.3, 4.17.4, 4.17.5, 4.17.6, 4.17.8, 4.17.9 
- 4.18.x
  - 4.18.0, 4.18.1, 4.18.10,4.18.11, 4.18.12, 4.18.13, 4.18.14, 4.18.15, 4.18.16, 4.18.3, 4.18.4, 4.18.5, 4.18.6, 4.18.7, 4.18.8, 4.18.9
- 4.19.x
  - 4.19.0, 4.19.1, 4.19.10, 4.19.11, 4.19.12, 4.19.2, 4.19.3, 4.19.4, 4.19.5, 4.19.6, 4.19.7, 4.19.8, 4.19.9 
- 4.20.x
  - 4.20.0,4.20.1, 4.20.10, 4.20.11, 4.20.12, 4.20.13, 4.20.2, 4.20.3, 4.20.4, 4.20.5, 4.20.6, 4.20.7, 4.20.8
- 5.0.x
  - 5.0.0, 5.0.0,5.0.1, 5.0.10, 5.0.11, 5.0.12, 5.0.13, 5.0.2, 5.0.3, 5.0.4, 5.0.5, 5.0.6, 5.0.7, 5.0.8, 5.0.9
- 5.1.x
  - 5.1.0, 5.1.1, 5.1.1,5.1.10, 5.1.11, 5.1.12, 5.1.14, 5.1.15, 5.1.16, 5.1.2, 5.1.3, 5.1.4, 5.1.5, 5.1.6, 5.1.7, 5.1.8, 5.1.9
- 5.2.x
  - 5.2.0, 5.2.1, 5.2.1, 5.2.10, 5.2.11, 5.2.12, 5.2.13, 5.2.14, 5.2.2, 5.2.3, 5.2.4, 5.2.5, 5.2.6, 5.2.7, 5.2.8, 5.2.9
- 5.3.x
  - 5.3.0, 5.3.1, 5.3.1, 5.3.10, 5.3.11, 5.3.12, 5.3.13, 5.3.2, 5.3.4, 5.3.5, 5.3.6, 5.3.7, 5.3.8, 5.3.9
- 5.4.x
  - 5.4.0, 5.4.1, 5.4.1, 5.4.10, 5.4.11, 5.4.12, 5.4.13, 5.4.14, 5.4.15, 5.4.2, 5.4.3, 5.4.4, 5.4.5, 5.4.6, 5.4.7, 5.4.8
- 5.5.x
  - 5.5.0, 5.5.1, 5.5.10, 5.5.11, 5.5.12, 5.5.13, 5.5.2, 5.5.3, 5.5.4, 5.5.5, 5.5.6, 5.5.6, 5.5.7, 5.5.8, 5.5.9
- 5.6.x
  - 5.6.0, 5.6.1, 5.6.10, 5.6.11, 5.6.12, 5.6.13, 5.6.14, 5.6.15, 5.6.2, 5.6.3, 5.6.4, 5.6.5, 5.6.6, 5.6.7, 5.6.8, 5.6.9
- 5.7.x
  - 5.7.0, 5.7.1, 5.7.10, 5.7.11, 5.7.12, 5.7.2, 5.7.3, 5.7.4, 5.7.5, 5.7.6, 5.7.7, 5.7.8, 5.7.9
- 5.8.x
  - 5.8.0, 5.8.1, 5.8.10, 5.8.11, 5.8.12, 5.8.13, 5.8.14, 5.8.2, 5.8.3, 5.8.4, 5.8.5, 5.8.6, 5.8.7, 5.8.8, 5.8.9
- 5.9.x
  - 5.9.0, 5.9.1, 5.9.10, 5.9.11, 5.9.12, 5.9.13, 5.9.14, 5.9.2, 5.9.3, 5.9.5, 5.9.6, 5.9.7, 5.9.8, 5.9.9
- 5.10.x
  - 5.10.0, 5.10.1, 5.10.10, 5.10.11, 5.10.12, 5.10.13, 5.10.14, 5.10.15, 5.10.16, 5.10.2, 5.10.3, 5.10.4, 5.10.5, 5.10.6, 5.10.7, 5.10.8, 5.10.9
- 5.11.x
  - 5.11.0, 5.11.1, 5.11.10, 5.11.11, 5.11.12, 5.11.13, 5.11.14, 5.11.15, 5.11.16, 5.11.2, 5.11.3, 5.11.4, 5.11.5, 5.11.6, 5.11.7, 5.11.8, 5.11.9
- 5.12.x
  - 5.12.0, 5.12.1, 5.12.10, 5.12.11, 5.12.12, 5.12.13, 5.12.2, 5.12.3, 5.12.4, 5.12.9
- 5.13.x
  - 5.13.0, 5.13.1, 5.13.2, 5.13.3, 5.13.4, 5.13.5, 5.13.6, 5.13.7, 5.13.8
- 5.14.x
  - 5.14.0, 5.14.1, 5.14.2, 5.14.3, 5.14.4, 5.14.5, 5.14.6, 5.14.7, 5.14.8, 5.14.9, 5.14.9, 5.14.10, 5.14.11, 5.14.12, 5.14.13, 5.14.14, 5.14.15
- 5.15.x
  - 5.15.0, 5.15.1, 5.15.2, 5.15.3, 5.15.4, 5.15.5, 5.15.6, 5.15.7, 5.15.8, 5.15.10, 5.15.11, 5.15.12, 5.15.13
- 5.16.x
  - 5.16.0, 5.16.1, 5.16.2, 5.16.4, 5.16.5, 5.16.6, 5.16.7
