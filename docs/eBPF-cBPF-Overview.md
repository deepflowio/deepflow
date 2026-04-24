# eBPF and cBPF in DeepFlow

This document provides a clear overview of how DeepFlow leverages both eBPF (extended Berkeley Packet Filter) and cBPF (classic Berkeley Packet Filter) technologies for comprehensive observability data collection.

## Overview

DeepFlow uses two complementary packet filtering technologies:

| Technology | Purpose | Data Source | Use Case |
|------------|---------|-------------|----------|
| **cBPF** | Network packet capture | AF_PACKET socket | Layer 3/4 flow metrics, network-level observability |
| **eBPF** | System call and application tracing | Kernel probes, tracepoints | Layer 7 protocol parsing, distributed tracing, profiling |

## What is cBPF (Classic BPF)?

cBPF is the original Berkeley Packet Filter, a technology for capturing and filtering network packets at the kernel level.

### How DeepFlow Uses cBPF

DeepFlow's **Dispatcher** component uses cBPF with AF_PACKET sockets to:

1. **Capture Network Traffic**: Intercepts packets from network interfaces
2. **Extract Flow Metadata**: Parses packet headers for IP addresses, ports, protocols
3. **Generate Flow Metrics**: Calculates throughput, latency, connection statistics
4. **Feed the Pipeline**: Sends captured packets to FlowGenerator for processing

```
┌─────────────────────────────────────────────────────────┐
│                     Linux Kernel                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Network Stack                       │    │
│  │    ┌───────────────────────────────────────┐    │    │
│  │    │   cBPF Filter (AF_PACKET socket)      │    │    │
│  │    │   - Packet capture                     │    │    │
│  │    │   - Header parsing                     │    │    │
│  │    │   - Traffic filtering                  │    │    │
│  │    └───────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │      Dispatcher          │
              │   (deepflow-agent)       │
              └─────────────────────────┘
```

### cBPF Capabilities

- **Zero Application Changes**: Works without modifying applications
- **Low Overhead**: Efficient kernel-level filtering
- **Protocol Agnostic**: Captures any network protocol
- **Full Packet Access**: Can inspect entire packet contents

## What is eBPF (Extended BPF)?

eBPF is a modern, programmable extension to BPF that allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.

### How DeepFlow Uses eBPF

DeepFlow's **EbpfCollector** component uses eBPF to:

1. **Trace System Calls**: Hooks into read/write syscalls to capture application data
2. **Parse L7 Protocols**: Identifies and parses HTTP, gRPC, MySQL, Redis, Kafka, etc.
3. **Distributed Tracing**: Correlates requests across services without code instrumentation
4. **Continuous Profiling**: Captures CPU, memory, and off-CPU profiling data

```
┌─────────────────────────────────────────────────────────┐
│                     Linux Kernel                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              eBPF Subsystem                      │    │
│  │    ┌───────────────────────────────────────┐    │    │
│  │    │  Kprobes/Tracepoints                  │    │    │
│  │    │  - syscall entry/exit hooks           │    │    │
│  │    │  - process lifecycle events           │    │    │
│  │    └───────────────────────────────────────┘    │    │
│  │    ┌───────────────────────────────────────┐    │    │
│  │    │  Uprobes                               │    │    │
│  │    │  - TLS/SSL interception               │    │    │
│  │    │  - Go runtime hooks                   │    │    │
│  │    │  - HTTP2/gRPC parsing                 │    │    │
│  │    └───────────────────────────────────────┘    │    │
│  │    ┌───────────────────────────────────────┐    │    │
│  │    │  Perf Events                          │    │    │
│  │    │  - CPU profiling                      │    │    │
│  │    │  - Stack trace collection             │    │    │
│  │    └───────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │     EbpfCollector        │
              │   (deepflow-agent)       │
              └─────────────────────────┘
```

### eBPF Probe Types Used by DeepFlow

| Probe Type | Overhead (ns) | Use Case |
|------------|---------------|----------|
| Kprobe | ~76 | Kernel function entry |
| Kretprobe | ~212 | Kernel function return |
| Tracepoint (entry) | ~96 | Stable kernel event hooks |
| Tracepoint (exit) | ~93 | Stable kernel event hooks |
| Uprobe | ~1287 | User-space function entry |
| Uretprobe | ~1931 | User-space function return |

### Supported Protocols via eBPF

DeepFlow's eBPF probes automatically detect and parse:

- **HTTP/HTTPS**: HTTP/1.x, HTTP/2
- **RPC**: gRPC, Dubbo, SOFARPC
- **Databases**: MySQL, PostgreSQL, Redis, MongoDB, Oracle
- **Messaging**: Kafka, MQTT, RocketMQ
- **Infrastructure**: DNS, FastCGI
- **Encrypted Traffic**: TLS handshake analysis

## Data Flow Architecture

The following diagram shows how cBPF and eBPF data flows through DeepFlow:

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Linux Kernel                                │
├─────────────────────────────┬───────────────────────────────────────┤
│     cBPF/AF_PACKET          │              eBPF                      │
│                             │                                        │
│  • Packet capture           │  • Syscall tracing (read/write)       │
│  • L3/L4 header parsing     │  • L7 protocol inference              │
│  • Flow identification      │  • TLS/SSL decryption hooks           │
│                             │  • Process lifecycle tracking         │
│                             │  • CPU/Memory profiling               │
└──────────────┬──────────────┴──────────────────┬────────────────────┘
               │                                  │
               ▼                                  ▼
┌──────────────────────────┐      ┌──────────────────────────────────┐
│       Dispatcher         │      │        EbpfCollector             │
│                          │      │                                   │
│  Generates:              │      │  Generates:                       │
│  • MetaPacket            │      │  • MetaPacket                     │
│  • L4 Flow data          │      │  • L7 Flow data                   │
│                          │      │  • Process events                 │
│                          │      │  • Profiling data                 │
└──────────────┬───────────┘      └─────────────────┬─────────────────┘
               │                                     │
               └─────────────────┬───────────────────┘
                                 │
                                 ▼
               ┌─────────────────────────────────────┐
               │          FlowGenerator              │
               │                                      │
               │  Aggregates and correlates:          │
               │  • L4 flows from Dispatcher          │
               │  • L7 flows from EbpfCollector       │
               │  • Creates unified flow view         │
               └─────────────────┬───────────────────┘
                                 │
                                 ▼
               ┌─────────────────────────────────────┐
               │         deepflow-server             │
               │                                      │
               │  Stores in ClickHouse:               │
               │  • flow_metrics                      │
               │  • flow_log (L4FlowLog, L7FlowLog)  │
               │  • profile                           │
               └─────────────────────────────────────┘
```

## Comparison: When Each Technology is Used

| Aspect | cBPF (Dispatcher) | eBPF (EbpfCollector) |
|--------|-------------------|----------------------|
| **Data Source** | Network packets | System calls, process events |
| **Protocol Layer** | L3/L4 (IP, TCP, UDP) | L7 (HTTP, gRPC, SQL, etc.) |
| **Visibility** | Network flows between hosts | Application request/response |
| **Encrypted Traffic** | Sees encrypted packets | Can decrypt via TLS hooks |
| **Kernel Version** | Works on all kernels | Requires Linux 4.14+ |
| **Performance Impact** | Very low | Low (< 1% CPU typically) |
| **Code Changes** | None required | None required |

## Key Differences

### cBPF Strengths
- **Universal compatibility**: Works on any Linux kernel
- **Network-centric view**: Ideal for flow-level metrics
- **Simple and efficient**: Low overhead packet filtering

### eBPF Strengths
- **Application awareness**: Understands L7 protocols
- **Distributed tracing**: Correlates requests across services
- **Encrypted traffic**: Can access data before/after encryption
- **Profiling**: CPU and memory profiling without agents

## Kernel Requirements

### For cBPF (Dispatcher)
- Any Linux kernel with AF_PACKET socket support
- No special kernel configuration required

### For eBPF (EbpfCollector)
- **Minimum**: Linux 4.14+
- **Recommended**: Linux 5.x+ for full feature support
- **Required kernel options**:
  ```
  CONFIG_BPF=y
  CONFIG_BPF_SYSCALL=y
  CONFIG_BPF_JIT=y
  CONFIG_HAVE_EBPF_JIT=y
  CONFIG_KPROBES=y
  CONFIG_UPROBES=y
  CONFIG_UPROBE_EVENTS=y
  ```

For detailed kernel version compatibility, see [kernel-versions.md](../agent/src/ebpf/docs/kernel-versions.md).

## Further Reading

- [eBPF Implementation Details](../agent/src/ebpf/README.md)
- [Probes and Maps Reference](../agent/src/ebpf/docs/probes-and-maps.md)
- [Data Flow Architecture](./design/data-flow.md)
- [Official eBPF Documentation](https://ebpf.io/)
