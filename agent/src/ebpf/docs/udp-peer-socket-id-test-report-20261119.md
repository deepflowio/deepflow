# UDP syscall 地址采集与 Peer Socket ID 隔离测试报告

> 本报告保留 `3f537eb` 在 Linux 4.19 上的历史测试结果；同日后续 tail-call 回迁见同目录 `v6.6-udp-chat-recovery-20261119.md` 第 14 节。原测试集已在 Linux 5.10 全量重跑，逐项对照见 [Linux 5.10 全量复测报告](udp-peer-socket-id-linux-5.10-test-report-20261119.md)。

## 1. 测试结论

2026-11-19 在节点 `k8s-node-27` 完成 Docker 编译、宿主机 eBPF 加载及真实 UDP 收发测试。
本报告中的 datadump 和 callback 来自实际运行日志，不是示例输出或合成数据。

| 项目 | 结果 |
| --- | --- |
| 七种 socket tracing eBPF 字节码变体重新编译 | 通过 |
| 宿主机加载 common 变体并进入 `TRACER_RUNNING` | 通过 |
| UDP syscall 地址及元数据：25 组场景、96 条预期事件 | 全部通过 |
| 短目标 sockaddr 导致发送失败，不产生对应 UDP callback | 通过 |
| 双 peer 隔离、同 IP 不同端口隔离、批量发送序号 | 通过 |
| 关闭功能的负向对照、通配本地地址回退 | 符合预期 |
| 开启/关闭时 Peer Map 容量 | 分别为 40960 / 1 |
| 宿主机运行时汇总检查 | 8/8 通过 |

**结论限定于本次 Linux 4.19.17 节点与列出的用例；不代表其他内核已通过运行时验证。**

## 2. 版本与环境

| 项目 | 内容 |
| --- | --- |
| 测试日期 | 2026-11-19，Asia/Shanghai |
| 工作目录 | `/home/jiping/deepflow/deepflow-1/deepflow` |
| 分支 / HEAD | `v6.6` / `3f537ebb89063f37cb6ad12d1fa372ecd67cf614` |
| 宿主机 | `k8s-node-27`，x86_64 |
| 宿主机内核 | `4.19.17-1.el7.x86_64` |
| 构建容器 / 镜像 | `deepflow-udp` / `hub.deepflow.yunshan.net/public/rust-build:1.31` |
| eBPF 编译器 | Clang/LLVM 11.0.0 |
| 运行方式 | `socket_tracer`、UDP C 样例、Python syscall 用例均直接在宿主机运行 |

验证内容：

- `fix(agent): 完善 UDP syscall 地址采集`：地址提取、入口 sockaddr 容量、datadump 元数据与公开 callback 长度。
- `fix(agent): isolate UDP peer metadata for socket tracing`：完整端点下的 peer ID 和 `cap_seq` 隔离，以及不可隔离时的回退。

### 实际使用的测试程序

**本次使用仓库 Rust sample 编译生成的 `socket_tracer`，不是完整的 `deepflow-agent`。**

- sample 源码：`agent/src/ebpf/samples/rust/socket-tracer/src/main.rs`。
- 在 Docker 内执行 `make clean`、`make socket-tracer`，重新生成并嵌入七种 eBPF 字节码；
  sample 构建产物为 `agent/src/ebpf/samples/rust/socket-tracer/target/release/socket_tracer`。
- 实际测试时，直接在宿主机 `k8s-node-27` 启动归档副本
  `/home/jiping/deepflow/deepflow-1/udp-validation-20261119.bkcXBN/socket_tracer`，
  等待 eBPF 加载并进入 `TRACER_RUNNING` 后，再运行 UDP 通信用例。
- 本报告中的 datadump 和 `UDP_PEER` callback 日志均来自该 `socket_tracer` 进程。
  UDP C 样例和 Python syscall 用例用于产生测试流量，不是采集程序。

该 sample 的临时采集调整说明见下一节；实际二进制校验值见第 6 节。
本次结果用于验证 socket tracing 路径，不替代完整 Agent 集成测试。

### 测试采集版本说明

本次基于上述 HEAD 和当时工作区构建。为了取得可关联的原始证据，仅临时调整 Rust sample：

1. 补齐工作区原有 datadump 调用缺失的 `ipaddr` / `port` 参数，适配当前分支 ABI。
2. datadump 临时选择 DNS 协议，输出 `SOURCE_FN`、`MSG_NUM`。
3. `UDP_PEER` callback 日志追加 `syscall_len` 和 DNS transaction ID（`txid`）。
4. 通过 `UDP_TEST_PEER_ID` 切换隔离功能，通过 `UDP_TEST_LOG` 指定日志位置。

**没有为测试修改内核程序或用户态库的实现逻辑；也不能将测试二进制表述为未经修改的 HEAD sample。**
实际测试采集源码保存为 `main.rs.test-instrumented`，原 sample 保存为 `main.rs.before`。
测试完成后已恢复临时调整，测试前后原有 tracked 工作区差异逐字节一致。

## 3. 构建与复核方法

### 3.1 Docker 内编译

以下为本次构建关键步骤的复现形式。编译在 Docker 内进行，运行时测试不在 Docker 内进行：

```bash
cd /home/jiping/deepflow/deepflow-1/deepflow
docker run --rm -it --net=host --privileged --name deepflow-udp \
  --workdir /work -v "$(pwd):/work" \
  hub.deepflow.yunshan.net/public/rust-build:1.31 bash

source /opt/rh/devtoolset-11/enable
cd /work/agent/src/ebpf
make clean
make socket-tracer SOCKET_TRACE_ELFS="user/socket_trace_bpf_common.c \
user/socket_trace_bpf_3_10_0.c user/socket_trace_bpf_5_2_plus.c \
user/socket_trace_bpf_kfunc.c user/socket_trace_bpf_kylin.c \
user/socket_trace_bpf_rt.c user/socket_trace_bpf_kprobe.c"
make -C test/udp-peer-id clean all
```

当时工作区的 Makefile 将 `SOCKET_TRACE_ELFS` 置空，因此使用命令行变量明确指定七个目标，
避免把旧的内嵌字节码当成新代码测试。完整输出见归档 `build.log`。

Rust 首次构建卡在 crates.io 索引更新；随后复用 registry 缓存，补齐 `Cargo.lock` 中固定版本的
`libc 0.2.157` 和 `rustix 0.38.37` 后离线构建成功，未修改依赖版本或 `Cargo.lock`。
上述命令不包含该次缓存准备和 sample 临时采集改动；精确采集版本应以归档源码及二进制为准。

### 3.2 宿主机用例与现有证据复核

宿主机编排脚本依次启动开启/关闭隔离的 tracer，等待 `TRACER_RUNNING` 后执行通信，
采集分段日志、读取 BPF Map 信息并执行校验。脚本及用例归档于：

```text
/home/jiping/deepflow/deepflow-1/udp-validation-20261119.bkcXBN
```

下列命令仅复核已保存的日志，不重新加载 eBPF，也不改变宿主机状态：

```bash
ARTIFACTS=/home/jiping/deepflow/deepflow-1/udp-validation-20261119.bkcXBN
cd /home/jiping/deepflow/deepflow-1/deepflow
python3 "$ARTIFACTS/verify_runtime.py" \
  "$ARTIFACTS/runtime-expectations.json" "$ARTIFACTS/syscall-runtime.log"
python3 agent/src/ebpf/test/udp-peer-id/verify_socket_tracer.py \
  "$ARTIFACTS/peer-enabled.log"
sha256sum -c "$ARTIFACTS/socket_tracer.sha256"
```

若需重新运行，先检查 `run_host_validation.py` 中的固定目录、53053 端口及宿主机权限，
使用保存的测试二进制与已构建 C 样例，并将源码、脚本、二进制复制到新的独立归档目录，
避免覆盖本次证据。tracer 初始化可能覆盖 `/usr/bin/deepflow-ebpfctl`，需先备份并在退出后恢复。

## 4. 测试覆盖

每条预期事件校验 PID/FD、方向、`txid`、远端 IP/端口、本地端口、callback 的
`cap_len` / `syscall_len`，以及对应 datadump 的 `SOURCE_FN` / `MSG_NUM` / `SYSCALL_LEN`。
除双栈本地地址缺失这一已知分支限制外，同时校验本地 IP。

所有场景的采集程序均为第 2 节说明的 Rust sample `socket_tracer`（完整测试采集源码见附录 H）。
下表“使用的测试程序”列列出流量发生程序及对应 case / 参数；Python syscall 场景的预期事件
由 `verify_runtime.py`（附录 B）关联 callback 和 datadump 校验。附录 A 至 H 提供完整源码，
既包含发生流量的程序，也包含校验器、编排脚本、构建文件及实际采集 sample。

| 场景 | 使用的测试程序 | 检查点 | 结果 |
| --- | --- | --- | --- |
| IPv4 / 原生 IPv6 `sendto` + `recvfrom` | `udp_syscall_cases.py`：`u4_to` / `u6_to`（附录 A） | 收发远端地址、端口和长度 | 通过 |
| IPv4 / 原生 IPv6 `sendmsg` + `recvmsg` | `udp_syscall_cases.py`：`u4_msg` / `u6_msg`（附录 A） | 从 syscall 参数采集未 connect UDP 的远端 | 通过 |
| IPv4 / 原生 IPv6 `sendmmsg` + `recvmmsg` | `udp_syscall_cases.py`：`u4_mmsg` / `u6_mmsg`（附录 A） | 首条地址、成功消息数、第二条发送长度 | 通过 |
| 双栈接收 IPv4-mapped 地址 | `udp_syscall_cases.py`：`dual_msg` / `dual_mmsg`（附录 A） | 远端归一化为 IPv4 | 通过 |
| AF_INET6 socket 使用 AF_INET 目标 sockaddr | `udp_syscall_cases.py`：`dual_send_ipv4_name()`，`dual4_sendto` / `dual4_sendmsg` / `dual4_sendmmsg`（附录 A） | 三种发送接口正确采集 IPv4 远端 | 通过 |
| IPv6 sockaddr 长度 / 入口容量 24 | `udp_syscall_cases.py`：`v6_24_to` / `v6_24_msg` / `v6_24_mmsg`（附录 A） | 三组收发接口正确采集 IPv6 地址及端口 | 通过 |
| IPv6 入口容量 16、返回长度 28 | `udp_syscall_cases.py`：`v6_short_to` / `v6_short_msg` / `v6_short_mmsg`（附录 A） | 不根据返回长度读取未复制的完整 IPv6 地址 | 通过 |
| IPv4 入口容量 8 / 不提供 `msg_name` | `udp_syscall_cases.py`：`v4_short` / `v4_noname`（附录 A） | 不使用旧远端地址 | 通过 |
| 同 FD 先完整接收，再短/零容量接收另一 peer | `udp_syscall_cases.py`：`stale_remote_case()`，`u4_stale`（附录 A） | 不复用前一报文的远端 | 通过 |
| `sendmmsg` 两条中仅第一条合法 | `udp_syscall_cases.py`：`v4_partial`（附录 A） | 成功数及 `MSG_NUM` 为 1，无第二条发送事件 | 通过 |
| 已 connect IPv4 / IPv6，地址长度 / 入口容量为 0 | `udp_syscall_cases.py`：`v4_connzero` / `v6_connzero`（附录 A） | 使用 socket 中真实已连接远端 | 通过 |
| 三种发送接口传入 8 字节短目标地址 | `udp_syscall_cases.py`：`short_send_case()`，`u4_invalid`；另检索原始 callback（附录 A） | 返回 EINVAL，无对应 `txid=2041` UDP callback | 通过 |
| 同 FD 按 A、B 接收，按 B、A 回复 | `udp_peer_server 127.0.0.1 53053` + `udp_peer_client 127.0.0.1 53053`；`verify_socket_tracer.py` 校验（附录 C、D、E） | peer ID 分离，同 peer 双向一致，序号各为 0、1 | 通过 |
| IPv4 / IPv6 同 IP 不同源端口 | `udp_syscall_cases.py`：`peer_ports_case()`，`u4_peerports` / `u6_peerports`（附录 A） | 按完整端点分离 peer ID | 通过 |
| 同 peer `sendmmsg` 两条不同长度 DNS | `udp_syscall_cases.py`：`u4_mmsg` / `u6_mmsg` 等成功发送两条的 case；`verify_runtime.py` 校验序号（附录 A、B） | 同 ID，序号 0、1，长度分别正确 | 通过 |
| 关闭隔离 | `UDP_TEST_PEER_ID=0` 的 `socket_tracer` + C 双 peer 样例；`run_host_validation.py` 校验物理 ID，并以 `verify_socket_tracer.py` 做负向对照（附录 C、D、E、F、H） | 共用物理 ID，总序号 0、1、2、3 | 符合预期 |
| 开启隔离但通配绑定缺少本地 IP | `UDP_TEST_PEER_ID=1` 的 `socket_tracer` + `udp_peer_server 0.0.0.0 53053` + `udp_peer_client 127.0.0.1 53053`；`run_host_validation.py` 校验（附录 C、D、F、H） | 回退物理 ID，总序号 0、1、2、3 | 符合预期 |

短地址发送的 EINVAL 由 `short_send_case()` 断言；没有 callback 是额外检查原始日志的结果，
不属于 `verify_runtime.py` 的 96 条正向预期事件校验。`run_host_validation.py`（附录 F）
统一启动上述程序、切换 sample 开关并采集 Map 信息，但不执行 Docker 编译或自动恢复
`/usr/bin/deepflow-ebpfctl`，这些步骤需按第 3、7 节单独处理。

## 5. 真实日志证据

本节路径均相对于第 3 节归档目录，行号为原文件行号；代码块内为原始日志摘录。
Rust 日志使用 UTC（`Z`），datadump 使用 Asia/Shanghai，二者相差 8 小时。

阅读字段时注意：

- datadump 的 `SEQ` 是 dump 记录序号；`DATA_SEQ` 才对应 callback 的 `cap_seq`。
- `MSG_NUM` 表示该次 mmsg 成功消息数，不代表每条消息都被输出。
- `LEN` / `SYSCALL_LEN` 为报文长度，不是 sockaddr 缓冲区容量；入口容量见通信日志。
- 原始日志中的 `TYPE unknown(7)` 保留原样，不将其解释为已完成请求/响应分类。

### 5.1 实际加载成功并进入运行态

来源：`tracer-enabled.log:107`、`tracer-enabled.log:287`。

```text
[2026-11-19T08:28:55.206Z INFO  socket_tracer::ebpf] [eBPF] INFO bpf load "socket-trace-bpf-linux-common" succeed.
[2026-11-19T08:28:57.383Z INFO  socket_tracer::ebpf] [eBPF] INFO [eBPF Kernel Adapt] Linux 4.19.17-1.el7.x86_64 adapt success. Set the status to TRACER_RUNNING
```

这证明本次不只是编译成功：common 程序通过当前内核加载，偏移适配完成并开始运行。

### 5.2 recvmsg 地址采集与公开 callback 长度

来源：`syscall-runtime.log:128`、`syscall-runtime.log:131`。

```text
2026-11-19 16:29:01.831985 [datadump] SEQ 24 <DNS> DIR in TYPE unknown(7) PID 8382 THREAD_ID 8382 COROUTINE_ID 0 FD 3 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN recvmsg(8) MSG_NUM 0 COMM python3 UDP 127.0.0.2.59687 > 127.0.0.1.53053 LEN 24 SYSCALL_LEN 24 SOCKET_ID 17950769352122307 TRACE_ID 17950769352122298 TCP_SEQ 0 DATA_SEQ 0 TLS false SyscallTime 2026-11-19 16:29:01.794594 SyscallMonoTime 17648398038594 us CapTime 2026-11-19 16:29:01.794594 CapMonoTime 17648398038594 us
UDP_PEER queue=0 process=python3 pid=8382 fd=3 direction=in socket_id=17950769352122307 cap_seq=0 local=127.0.0.1:53053 remote=127.0.0.2:59687 cap_len=24 syscall_len=24 txid=2005
```

PID、FD、方向、socket ID 与序号对应；datadump 展示 `recvmsg(8)`，callback 的
`syscall_len` 仍为真实长度 24。本次 96 条预期事件均执行相同长度检查，未观察到内部元数据高位泄漏。

### 5.3 sendmmsg 两条消息：长度独立，序号连续

来源：`syscall-runtime.log:234`、`syscall-runtime.log:237`、
`syscall-runtime.log:244`、`syscall-runtime.log:247`。

```text
2026-11-19 16:29:01.896835 [datadump] SEQ 35 <DNS> DIR out TYPE unknown(7) PID 8382 THREAD_ID 8382 COROUTINE_ID 0 FD 4 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN sendmmsg(9) MSG_NUM 2 COMM python3 UDP 127.0.0.2.42897 > 127.0.0.1.53053 LEN 24 SYSCALL_LEN 24 SOCKET_ID 17950769352122313 TRACE_ID 17950769352122301 TCP_SEQ 0 DATA_SEQ 0 TLS false SyscallTime 2026-11-19 16:29:01.896695 SyscallMonoTime 17648398140695 us CapTime 2026-11-19 16:29:01.896778 CapMonoTime 17648398140778 us
UDP_PEER queue=0 process=python3 pid=8382 fd=4 direction=out socket_id=17950769352122313 cap_seq=0 local=127.0.0.2:42897 remote=127.0.0.1:53053 cap_len=24 syscall_len=24 txid=2009
2026-11-19 16:29:01.911790 [datadump] SEQ 36 <DNS> DIR out TYPE unknown(7) PID 8382 THREAD_ID 8382 COROUTINE_ID 0 FD 4 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN sendmmsg(9) MSG_NUM 2 COMM python3 UDP 127.0.0.2.42897 > 127.0.0.1.53053 LEN 37 SYSCALL_LEN 37 SOCKET_ID 17950769352122313 TRACE_ID 17950769352122301 TCP_SEQ 0 DATA_SEQ 1 TLS false SyscallTime 2026-11-19 16:29:01.896695 SyscallMonoTime 17648398140695 us CapTime 2026-11-19 16:29:01.896778 CapMonoTime 17648398140778 us
UDP_PEER queue=0 process=python3 pid=8382 fd=4 direction=out socket_id=17950769352122313 cap_seq=1 local=127.0.0.2:42897 remote=127.0.0.1:53053 cap_len=37 syscall_len=37 txid=2010
```

两条消息共享 ID `17950769352122313`，`cap_seq` 为 0、1；第二条正确使用 37 字节，
没有沿用第一条的 24 字节。两条的 `MSG_NUM` 均为此次成功消息数 2。

部分成功的补充证据，来源：`runtime-communication.log:17`、`syscall-runtime.log:840`。

```text
[COMM OK] v4_partial sent=1 recv=1 input_capacity=128 returned_namelen=16
2026-11-19 16:29:02.506172 [datadump] SEQ 98 <DNS> DIR out TYPE unknown(7) PID 8382 THREAD_ID 8382 COROUTINE_ID 0 FD 4 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN sendmmsg(9) MSG_NUM 1 COMM python3 UDP 127.0.0.2.43710 > 127.0.0.1.53053 LEN 24 SYSCALL_LEN 24 SOCKET_ID 306181145503834040 TRACE_ID 306181145503834036 TCP_SEQ 0 DATA_SEQ 0 TLS false SyscallTime 2026-11-19 16:29:02.506090 SyscallMonoTime 17648398750089 us CapTime 2026-11-19 16:29:02.506138 CapMonoTime 17648398750137 us
```

### 5.4 IPv6 接收入口容量：24 字节可提取，16 字节不误读

来源：`runtime-communication.log:11`、`runtime-communication.log:12`，
`syscall-runtime.log:565`、`syscall-runtime.log:623`。

```text
[COMM OK] v6_24_msg sent=1 recv=1 input_capacity=24 returned_namelen=28
[COMM OK] v6_short_msg sent=1 recv=1 input_capacity=16 returned_namelen=28
UDP_PEER queue=0 process=python3 pid=8382 fd=3 direction=in socket_id=17950769352122336 cap_seq=0 local=::1:53053 remote=::1:38937 cap_len=24 syscall_len=24 txid=2021
UDP_PEER queue=0 process=python3 pid=8382 fd=3 direction=in socket_id=17950769352122339 cap_seq=0 local=::1:53053 remote=:::0 cap_len=24 syscall_len=24 txid=2023
```

两次返回的 `msg_namelen` 都是 28，但实际可复制容量分别只有 24 和 16。
24 字节包含 IPv6 地址和端口所需字段；16 字节不足，因此第二次远端保持未知。
`remote=:::0` 是 sample 将 IP `::` 与端口 `0` 直接拼接的输出，并非一个有效端点字面量。

### 5.5 同一 FD 的历史远端不串到短/零容量接收

来源：`runtime-communication.log:20` 至 `runtime-communication.log:22`；
`syscall-runtime.log:1027`、`syscall-runtime.log:1047`、`syscall-runtime.log:1067`。

```text
[COMM OK] stale remote capacity=16 output=16
[COMM OK] stale remote capacity=8 output=16
[COMM OK] stale remote capacity=0 output=0
UDP_PEER queue=0 process=python3 pid=8382 fd=3 direction=in socket_id=450296333579689915 cap_seq=0 local=127.0.0.1:53053 remote=127.0.0.2:47280 cap_len=24 syscall_len=24 txid=2038
UDP_PEER queue=0 process=python3 pid=8382 fd=3 direction=in socket_id=450296333579689914 cap_seq=1 local=127.0.0.1:53053 remote=0.0.0.0:0 cap_len=24 syscall_len=24 txid=2039
UDP_PEER queue=0 process=python3 pid=8382 fd=3 direction=in socket_id=450296333579689914 cap_seq=2 local=127.0.0.1:53053 remote=0.0.0.0:0 cap_len=24 syscall_len=24 txid=2040
```

后两条没有错误复用第一条的 `127.0.0.2:47280`。端点完整时输出 peer ID，
端点不完整时回退物理 ID，因此此处 ID 改变符合预期。

### 5.6 双 peer：同一 FD，A、B 接收，B、A 回复

来源：`peer-enabled.log:60`、`peer-enabled.log:70`、
`peer-enabled.log:80`、`peer-enabled.log:90`。

```text
2026-11-19 16:29:00.32487 [datadump] SEQ 6 <DNS> DIR in TYPE unknown(7) PID 8253 THREAD_ID 8253 COROUTINE_ID 0 FD 3 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN recvfrom(6) MSG_NUM 0 COMM udp_peer_server UDP 127.0.0.2.40653 > 127.0.0.1.53053 LEN 24 SYSCALL_LEN 24 SOCKET_ID 882641897807257525 TRACE_ID 882641897807257524 TCP_SEQ 0 DATA_SEQ 0 TLS false SyscallTime 2026-11-19 16:28:59.996039 SyscallMonoTime 17648396240039 us CapTime 2026-11-19 16:28:59.996039 CapMonoTime 17648396240039 us
2026-11-19 16:29:00.32604 [datadump] SEQ 7 <DNS> DIR in TYPE unknown(7) PID 8253 THREAD_ID 8253 COROUTINE_ID 0 FD 3 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN recvfrom(6) MSG_NUM 0 COMM udp_peer_server UDP 127.0.0.3.37550 > 127.0.0.1.53053 LEN 24 SYSCALL_LEN 24 SOCKET_ID 882641897807257526 TRACE_ID 882641897807257524 TCP_SEQ 0 DATA_SEQ 0 TLS false SyscallTime 2026-11-19 16:28:59.996067 SyscallMonoTime 17648396240066 us CapTime 2026-11-19 16:28:59.996067 CapMonoTime 17648396240066 us
2026-11-19 16:29:00.32688 [datadump] SEQ 8 <DNS> DIR out TYPE unknown(7) PID 8253 THREAD_ID 8253 COROUTINE_ID 0 FD 3 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN sendto(5) MSG_NUM 0 COMM udp_peer_server UDP 127.0.0.1.53053 > 127.0.0.3.37550 LEN 24 SYSCALL_LEN 24 SOCKET_ID 882641897807257526 TRACE_ID 882641897807257524 TCP_SEQ 0 DATA_SEQ 1 TLS false SyscallTime 2026-11-19 16:28:59.996072 SyscallMonoTime 17648396240072 us CapTime 2026-11-19 16:28:59.996095 CapMonoTime 17648396240095 us
2026-11-19 16:29:00.32766 [datadump] SEQ 9 <DNS> DIR out TYPE unknown(7) PID 8253 THREAD_ID 8253 COROUTINE_ID 0 FD 3 ROLE unknown CONTAINER_ID null SOURCE 0 SOURCE_FN sendto(5) MSG_NUM 0 COMM udp_peer_server UDP 127.0.0.1.53053 > 127.0.0.2.40653 LEN 24 SYSCALL_LEN 24 SOCKET_ID 882641897807257525 TRACE_ID 0 TCP_SEQ 0 DATA_SEQ 1 TLS false SyscallTime 2026-11-19 16:28:59.996100 SyscallMonoTime 17648396240100 us CapTime 2026-11-19 16:28:59.996115 CapMonoTime 17648396240115 us
```

对应 callback，来源：`peer-enabled.log:63`、`peer-enabled.log:73`、
`peer-enabled.log:83`、`peer-enabled.log:93`。

```text
UDP_PEER queue=0 process=udp_peer_server pid=8253 fd=3 direction=in socket_id=882641897807257525 cap_seq=0 local=127.0.0.1:53053 remote=127.0.0.2:40653 cap_len=24 syscall_len=24 txid=4369
UDP_PEER queue=0 process=udp_peer_server pid=8253 fd=3 direction=in socket_id=882641897807257526 cap_seq=0 local=127.0.0.1:53053 remote=127.0.0.3:37550 cap_len=24 syscall_len=24 txid=8738
UDP_PEER queue=0 process=udp_peer_server pid=8253 fd=3 direction=out socket_id=882641897807257526 cap_seq=1 local=127.0.0.1:53053 remote=127.0.0.3:37550 cap_len=24 syscall_len=24 txid=8738
UDP_PEER queue=0 process=udp_peer_server pid=8253 fd=3 direction=out socket_id=882641897807257525 cap_seq=1 local=127.0.0.1:53053 remote=127.0.0.2:40653 cap_len=24 syscall_len=24 txid=4369
```

| 服务端 PID / FD | Peer | 请求 ID / 序号 | 响应 ID / 序号 |
| --- | --- | --- | --- |
| 8253 / 3 | A：127.0.0.2:40653 | 882641897807257525 / 0 | 882641897807257525 / 1 |
| 8253 / 3 | B：127.0.0.3:37550 | 882641897807257526 / 0 | 882641897807257526 / 1 |

相同 PID、FD 下两个 peer 的 ID 不同；同一 peer 双向 ID 一致，序号独立，不受交错响应影响。
来源 `peer-enabled-verification.log:1` 的校验结果：

```text
[OK] UDP peer socket ID isolation
  peer=127.0.0.2 fd=3 socket_id=882641897807257525 cap_seq=0,1
  peer=127.0.0.3 fd=3 socket_id=882641897807257526 cap_seq=0,1
```

### 5.7 关闭功能的负向对照

来源：`peer-disabled.log:5`、`peer-disabled.log:25`、
`peer-disabled.log:35`、`peer-disabled.log:45`。

```text
UDP_PEER queue=0 process=udp_peer_server pid=10316 fd=3 direction=in socket_id=162065957615794923 cap_seq=0 local=127.0.0.1:53053 remote=127.0.0.2:53814 cap_len=24 syscall_len=24 txid=4369
UDP_PEER queue=0 process=udp_peer_server pid=10316 fd=3 direction=in socket_id=162065957615794923 cap_seq=1 local=127.0.0.1:53053 remote=127.0.0.3:34021 cap_len=24 syscall_len=24 txid=8738
UDP_PEER queue=0 process=udp_peer_server pid=10316 fd=3 direction=out socket_id=162065957615794923 cap_seq=2 local=127.0.0.1:53053 remote=127.0.0.3:34021 cap_len=24 syscall_len=24 txid=8738
UDP_PEER queue=0 process=udp_peer_server pid=10316 fd=3 direction=out socket_id=162065957615794923 cap_seq=3 local=127.0.0.1:53053 remote=127.0.0.2:53814 cap_len=24 syscall_len=24 txid=4369
```

两个 peer 共用物理 ID，总序号 0、1、2、3。隔离校验器按预期拒绝此日志，
来源 `peer-disabled-negative-verification.log:1`：

```text
[FAIL] peer 127.0.0.2 cap_seq is [0, 3], expected [0, 1]
```

**这是负向对照成功，不是本次功能测试失败**：它证明校验器能够识别未开启隔离的行为。

### 5.8 通配绑定缺少本地 IP 时回退

来源：`peer-wildcard.log:5`、`peer-wildcard.log:25`、
`peer-wildcard.log:35`、`peer-wildcard.log:45`。

```text
UDP_PEER queue=0 process=udp_peer_server pid=8949 fd=3 direction=in socket_id=17950769352122340 cap_seq=0 local=0.0.0.0:53053 remote=127.0.0.2:58117 cap_len=24 syscall_len=24 txid=4369
UDP_PEER queue=0 process=udp_peer_server pid=8949 fd=3 direction=in socket_id=17950769352122340 cap_seq=1 local=0.0.0.0:53053 remote=127.0.0.3:57476 cap_len=24 syscall_len=24 txid=8738
UDP_PEER queue=0 process=udp_peer_server pid=8949 fd=3 direction=out socket_id=17950769352122340 cap_seq=2 local=0.0.0.0:53053 remote=127.0.0.3:57476 cap_len=24 syscall_len=24 txid=8738
UDP_PEER queue=0 process=udp_peer_server pid=8949 fd=3 direction=out socket_id=17950769352122340 cap_seq=3 local=0.0.0.0:53053 remote=127.0.0.2:58117 cap_len=24 syscall_len=24 txid=4369
```

本分支不含 UDP 本地 IP 补偿，`0.0.0.0` 不构成完整本地端点，因此即使开启隔离也回退物理 ID。
此项验证的是回退正确，不是通配绑定也已实现 peer 隔离。

### 5.9 BPF Map 真实容量

通过宿主机 BPF syscall 读取 Map 信息，以下分别为 `maps-enabled.json` 和
`maps-disabled.json` 中的 Peer Map 对象原文；`type=9` 为 LRU_HASH。

开启：

```json
  {
    "name": "__udp_peer_map",
    "id": 4257,
    "type": 9,
    "key_size": 48,
    "value_size": 16,
    "capacity": 40960
  }
```

关闭：

```json
  {
    "name": "__udp_peer_map",
    "id": 4287,
    "type": 9,
    "key_size": 48,
    "value_size": 16,
    "capacity": 1
  }
```

### 5.10 自动校验汇总

来源：`runtime-verification.log:36`。

```text
[OK] 96 events verified: tuples, callback lengths, SOURCE_FN, MSG_NUM, sendmmsg and peer-port sequences
```

`runtime-results.json` 的八项检查均为 `success: true`，涵盖开启/关闭时 Map 容量、
双 peer 隔离、syscall 通信、地址及元数据、通配回退、关闭后的物理 ID，以及负向校验器。
源码契约检查也通过，原始记录分别为 `static-address-contracts.log`、`static-peer-contracts.log`。

## 6. 归档索引

归档目录为本节点本地文件，**未随本 Markdown 一起加入仓库**；跨机器复核需另外传递归档。
文档已内嵌关键原始证据，完整上下文、脚本和实际二进制仍以归档为准。

| 文件 | 用途 |
| --- | --- |
| `environment.log`、`build.log` | 节点、内核、版本及完整构建日志 |
| `tracer-enabled.log`、`tracer-disabled.log` | 开启/关闭时完整 tracer 输出 |
| `syscall-runtime.log` | syscall 测试原始 datadump 和 callback |
| `runtime-communication.log`、`runtime-expectations.json` | 实际 syscall 结果、入口容量和预期事件 |
| `runtime-verification.log`、`runtime-results.json`、`host-validation.log` | 逐场景校验及总结果 |
| `peer-enabled.log`、`peer-disabled.log`、`peer-wildcard.log` | 开启、关闭、通配回退原始证据 |
| `peer-enabled-verification.log`、`peer-disabled-negative-verification.log` | 正向和负向隔离校验结果 |
| `maps-enabled.json`、`maps-disabled.json`、`cleanup-maps.json` | Map 容量与释放记录 |
| `udp_syscall_cases.py`、`verify_runtime.py`、`run_host_validation.py` | 用例、证据校验和宿主机编排源码 |
| `main.rs.before`、`main.rs.test-instrumented` | 原 sample 与实际测试采集版本 |
| `socket_tracer`、`socket_tracer.sha256` | 实际运行二进制及 SHA256 |
| `worktree.before.patch`、`worktree.final.patch` | 测试前后原工作区差异，一致 |

实际测试二进制 SHA256：

```text
270dbd861d8c11ad762ef8887e5179514d48c5d5a01dd04168af792f33aaa3ee
```

## 7. 清理与范围限制

### 已完成清理

- 两个测试 tracer 进程及 UDP 测试进程已退出，本次创建的四个 UDP peer 相关 Map 已释放。
- `kprobe_events` 与运行前一致，`kptr_restrict`、`perf_event_paranoid` 未改变。
- 恢复 tracer 初始化时覆盖的 `/usr/bin/deepflow-ebpfctl`。
- 专用 `deepflow-udp` 容器已停止并自动移除，未停止其他已有容器或服务。
- 测试时的临时 tracked 源码改动已恢复，原有未提交修改保留；本报告后续随 tail-call 契约测试和恢复记录一并补充提交，未推送。

### 未覆盖范围与已知边界

- 本报告对应的历史轮次仅在 Linux `4.19.17-1.el7.x86_64` 完成运行时加载；同日后续 Linux 5.10 已完成全量复测，详见独立报告。4.14、6.8 等仍未实测。
  七种 eBPF 变体编译通过，不等于七种内核加载通过。
- 未进行完整 Agent 构建、完整 CI、LRU 耗尽测试或并发压力测试。
- 当前 `recvmmsg` 仅输出首条消息；`sendmmsg` 的 DNS 附加路径输出第二条。
  未宣称任意 batch 全量采集，也未测试同 batch 中不同目标 peer。
- v6.6 缺少 UDP 本地 IP 补偿；本地端点不完整时仍可能共用物理 socket ID。
- 参考 MR 7554、7595 的描述与当前仓库样例设计测试。GitLab 评论接口返回 401，
  无法读取评论中的原始测试附件；补充用例依据场景重新编写，不是直接运行附件源码。

## 8. 参考

- [PR 11965](https://github.com/deepflowio/deepflow/pull/11965)
- [MR 7554](https://gitlab.yunshan.net/yunshan/deepflow-core/-/merge_requests/7554)
- [MR 7595](https://gitlab.yunshan.net/yunshan/deepflow-core/-/merge_requests/7595)
- 仓库双 peer 样例与操作步骤：`agent/src/ebpf/test/udp-peer-id/README.md`。
- 仓库隔离设计：`agent/src/ebpf/docs/udp-peer-socket-id-design.md`。

## 附录：本次测试源代码

以下是本次测试相关程序的完整源码快照，不使用省略号替代实现。
附录 A、B、F、H 从实际测试归档直接复制；附录 C、D、E、G 来自本次测试 HEAD
`3f537ebb89063f37cb6ad12d1fa372ecd67cf614`，并与当前仓库对应文件逐字节核对一致。
除附录 H 清理了一处原文件行尾空格以外，其余内容均逐字节保留；源文件内已有注释保持原样。
各节 SHA256 对应本文代码块内容（含末尾换行），便于从本文提取后校验。

| 附录 | 文件 | 职责 |
| --- | --- | --- |
| A | `udp_syscall_cases.py` | 通过 libc syscall 接口产生 IPv4 / IPv6 UDP 流量，并生成预期事件 JSON |
| B | `verify_runtime.py` | 对照预期事件校验 callback、datadump、长度、端点和 peer 序号 |
| C | `udp_peer_server.c` | 同一 FD 接收 A、B，按 B、A 回复 |
| D | `udp_peer_client.c` | 两个不同 IP 的客户端 peer 产生交错请求/响应 |
| E | `verify_socket_tracer.py` | 校验双 peer 的 ID、双向一致性和独立序号 |
| F | `run_host_validation.py` | 宿主机启动/停止 tracer、运行用例、检查 Map 和回退、生成汇总 |
| G | `Makefile` | 构建 C 双 peer 服务端及客户端 |
| H | `main.rs.test-instrumented` | 实际使用的 Rust `socket_tracer` sample，含临时测试采集改动 |

依赖说明：A、B、E、F 使用 Python 3 标准库，A 通过 ctypes 调用宿主机 libc；
C、D 使用 Linux/POSIX socket API；H 依赖仓库 sample 的 Cargo 工程及 eBPF 构建产物，
不是可单独用 `rustc` 编译的独立文件。

编排脚本含本节点绝对路径和 x86_64 BPF syscall 编号，不应未经检查直接用于其他节点或架构。
完整重跑仍需第 3 节的构建、独立证据目录及第 7 节的备份/清理步骤。

### A. UDP syscall 通信与预期事件生成

文件名：`udp_syscall_cases.py`。

来源：`/home/jiping/deepflow/deepflow-1/udp-validation-20261119.bkcXBN/udp_syscall_cases.py`。

SHA256：`db49c373f088900f3b1942710d1256298e0af8ad3a85345b04966c0d7793414a`。

```python
#!/usr/bin/env python3

import ctypes
import errno
import json
import os
import socket
import struct
import sys
import time


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.sendmsg.restype = ctypes.c_ssize_t
LIBC.recvmsg.restype = ctypes.c_ssize_t
LIBC.sendto.restype = ctypes.c_ssize_t
LIBC.recvfrom.restype = ctypes.c_ssize_t
PORT = 53053
EXPECTATIONS = []
NEXT_ID = 2000


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


class Msghdr(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_void_p), ("namelen", ctypes.c_uint),
        ("iov", ctypes.POINTER(Iovec)), ("iovlen", ctypes.c_size_t),
        ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
        ("flags", ctypes.c_int),
    ]


class Mmsghdr(ctypes.Structure):
    _fields_ = [("header", Msghdr), ("length", ctypes.c_uint)]


def checked(result, operation):
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, "{}: {}".format(operation, os.strerror(code)))
    return result


def dns_packet(response=False, longer=False):
    global NEXT_ID
    NEXT_ID += 1
    labels = [b"longer", b"example", b"test"] if longer else [b"a", b"test"]
    name = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", NEXT_ID, 0x8180 if response else 0x0100,
                       1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)


def sockaddr(family, address):
    ip, port = address[:2]
    if family == socket.AF_INET:
        return struct.pack("=H", family) + struct.pack("!H", port) + socket.inet_pton(family, ip) + b"\x00" * 8
    return struct.pack("=H", family) + struct.pack("!H", port) + b"\x00" * 4 + socket.inet_pton(family, ip) + b"\x00" * 4


def normalized(ip):
    return ip.split("::ffff:", 1)[-1] if ip.startswith("::ffff:") else ip


def expected(case, sock, direction, packet, remote, source, count=0,
             complete=True, extra=False):
    EXPECTATIONS.append(dict(
        case=case, pid=os.getpid(), fd=sock.fileno(), direction=direction,
        txid=struct.unpack("!H", packet[:2])[0], length=len(packet),
        local_ip=normalized(sock.getsockname()[0]),
        local_port=sock.getsockname()[1], remote_ip=normalized(remote[0]),
        remote_port=remote[1], source=source, msg_num=count,
        complete=complete, extra=extra,
    ))


def send_packets(sock, packets, destination, mode, name_length=None,
                 partial=False, name_zero=False, address_family=None):
    encoded = sockaddr(sock.family if address_family is None else address_family, destination)
    address = ctypes.create_string_buffer(encoded)
    capacity = len(encoded) if name_length is None else name_length
    if mode == "sendto":
        packet = ctypes.create_string_buffer(packets[0])
        checked(LIBC.sendto(sock.fileno(), packet, len(packets[0]), 0,
                            address, capacity), mode)
        return 1
    messages = (Mmsghdr * len(packets))()
    keepalive = [address]
    for index, packet in enumerate(packets):
        data = ctypes.create_string_buffer(packet)
        vectors = (Iovec * 1)(Iovec(ctypes.cast(data, ctypes.c_void_p), len(packet)))
        keepalive.extend([data, vectors])
        header = messages[index].header
        header.name = ctypes.cast(address, ctypes.c_void_p)
        header.namelen = 0 if name_zero else (8 if partial and index else capacity)
        header.iov = vectors
        header.iovlen = 1
    if mode == "sendmsg":
        checked(LIBC.sendmsg(sock.fileno(), ctypes.byref(messages[0].header), 0), mode)
        return 1
    return checked(LIBC.sendmmsg(sock.fileno(), messages, len(packets), 0), mode)


def receive_packets(sock, mode, count=1, capacity=128, with_name=True):
    addresses = [ctypes.create_string_buffer(128) for unused in range(count)]
    buffers = [ctypes.create_string_buffer(2048) for unused in range(count)]
    if mode == "recvfrom":
        name_length = ctypes.c_uint(capacity)
        size = checked(LIBC.recvfrom(sock.fileno(), buffers[0], 2048, 0,
                                    addresses[0] if with_name else None,
                                    ctypes.byref(name_length) if with_name else None), mode)
        return [buffers[0].raw[:size]], name_length.value
    vectors = [(Iovec * 1)(Iovec(ctypes.cast(buffer, ctypes.c_void_p), 2048)) for buffer in buffers]
    messages = (Mmsghdr * count)()
    for index in range(count):
        header = messages[index].header
        header.name = ctypes.cast(addresses[index], ctypes.c_void_p) if with_name else None
        header.namelen = capacity
        header.iov = vectors[index]
        header.iovlen = 1
    if mode == "recvmsg":
        size = checked(LIBC.recvmsg(sock.fileno(), ctypes.byref(messages[0].header), 0), mode)
        return [buffers[0].raw[:size]], messages[0].header.namelen
    received = checked(LIBC.recvmmsg(sock.fileno(), messages, count,
                                   0x10000, None), mode)
    return [buffers[index].raw[:messages[index].length] for index in range(received)], messages[0].header.namelen


def make_pair(family, dual=False):
    server = socket.socket(family, socket.SOCK_DGRAM)
    client_family = socket.AF_INET if dual else family
    client = socket.socket(client_family, socket.SOCK_DGRAM)
    for sock in (server, client):
        timeout = struct.pack("ll", 3, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if dual else 1)
    server.bind(("::" if dual else "::1" if family == socket.AF_INET6 else "127.0.0.1", PORT))
    client.bind(("::1" if client_family == socket.AF_INET6 else "127.0.0.2", 0))
    return server, client


def run_case(case, family, send_mode, recv_mode, dual=False, capacity=128,
             send_length=None, count=1, partial=False, connected=False,
             name_zero=False, with_name=True):
    LIBC.prctl(15, case.encode("ascii")[:15], 0, 0, 0)
    server, client = make_pair(family, dual)
    try:
        server_address = ("127.0.0.1" if dual else server.getsockname()[0], PORT)
        if connected:
            client.connect(server_address)
            server.connect(client.getsockname())
        packets = [dns_packet(longer=index > 0) for index in range(count)]
        sent = send_packets(client, packets, server_address, send_mode,
                            send_length, partial, name_zero)
        assert sent == (1 if partial else count), (case, sent)
        received, returned_length = receive_packets(server, recv_mode,
                                                    count if recv_mode == "recvmmsg" else 1,
                                                    capacity, with_name)
        assert received == packets[:sent], (case, received, packets[:sent])
        client_address = client.getsockname()
        receive_complete = connected or (with_name and capacity >= (24 if family == socket.AF_INET6 else 16))
        expected(case, client, "out", packets[0], server_address, send_mode,
                 sent if send_mode == "sendmmsg" else 0)
        if sent == 2:
            expected(case, client, "out", packets[1], server_address, send_mode, sent, extra=True)
        expected(case, server, "in", packets[0], client_address, recv_mode,
                 len(received) if recv_mode == "recvmmsg" else 0,
                 complete=receive_complete)
        if receive_complete and not dual:
            response = dns_packet(response=True)
            send_packets(server, [response], client_address, "sendmsg",
                         24 if family == socket.AF_INET6 and send_length == 24 else None)
            echoed, unused_length = receive_packets(client, "recvmsg", capacity=capacity if connected else 128)
            assert echoed == [response]
            expected(case, server, "out", response, client_address, "sendmsg")
            expected(case, client, "in", response, server_address, "recvmsg")
        print("[COMM OK] {} sent={} recv={} input_capacity={} returned_namelen={}".format(
            case, sent, len(received), capacity, returned_length), flush=True)
    finally:
        client.close()
        server.close()
        time.sleep(0.05)


def stale_remote_case():
    case = "u4_stale"
    LIBC.prctl(15, case.encode("ascii"), 0, 0, 0)
    server, first = make_pair(socket.AF_INET)
    second = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    second.bind(("127.0.0.3", 0))
    try:
        for client, capacity in ((first, 16), (second, 8), (second, 0)):
            packet = dns_packet()
            send_packets(client, [packet], server.getsockname(), "sendmsg")
            received, returned_length = receive_packets(server, "recvmsg", capacity=capacity)
            assert received == [packet]
            expected(case, client, "out", packet, server.getsockname(), "sendmsg")
            expected(case, server, "in", packet, client.getsockname(), "recvmsg", complete=capacity >= 16)
            print("[COMM OK] stale remote capacity={} output={}".format(capacity, returned_length), flush=True)
    finally:
        for sock in (server, first, second):
            sock.close()


def short_send_case():
    case = "u4_invalid"
    LIBC.prctl(15, case.encode("ascii"), 0, 0, 0)
    server, client = make_pair(socket.AF_INET)
    try:
        packet = dns_packet()
        for mode in ("sendto", "sendmsg", "sendmmsg"):
            try:
                send_packets(client, [packet], server.getsockname(), mode, name_length=8)
            except OSError as error:
                assert error.errno == errno.EINVAL, error
            else:
                raise AssertionError("short sockaddr unexpectedly accepted")
        print("[COMM OK] invalid sockaddr rejected for sendto/sendmsg/sendmmsg", flush=True)
    finally:
        server.close()
        client.close()


def dual_send_ipv4_name(mode):
    case = "dual4_" + mode
    LIBC.prctl(15, case.encode("ascii")[:15], 0, 0, 0)
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("127.0.0.1", PORT))
    client.bind(("::ffff:127.0.0.2", 0))
    for sock in (server, client):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 3, 0))
    try:
        packets = [dns_packet()]
        if mode == "sendmmsg":
            packets.append(dns_packet(longer=True))
        count = send_packets(client, packets, server.getsockname(), mode, address_family=socket.AF_INET)
        received, unused = receive_packets(server, "recvmmsg" if count == 2 else "recvmsg", count=count)
        assert received == packets
        expected(case, client, "out", packets[0], server.getsockname(), mode, count if mode == "sendmmsg" else 0)
        if count == 2:
            expected(case, client, "out", packets[1], server.getsockname(), mode, count, extra=True)
        expected(case, server, "in", packets[0], client.getsockname(), "recvmmsg" if count == 2 else "recvmsg", count if count == 2 else 0)
        print("[COMM OK] {} AF_INET6 socket with AF_INET msg_name".format(case), flush=True)
    finally:
        server.close()
        client.close()


def peer_ports_case(family):
    case = "u6_peerports" if family == socket.AF_INET6 else "u4_peerports"
    LIBC.prctl(15, case.encode("ascii"), 0, 0, 0)
    server, first = make_pair(family)
    second = socket.socket(family, socket.SOCK_DGRAM)
    second.bind((first.getsockname()[0], 0))
    clients = [first, second]
    try:
        requests = [dns_packet(), dns_packet()]
        for client, packet in zip(clients, requests):
            send_packets(client, [packet], server.getsockname(), "sendmsg")
            expected(case, client, "out", packet, server.getsockname(), "sendmsg")
        for client, packet in zip(clients, requests):
            received, unused = receive_packets(server, "recvmsg")
            assert received == [packet]
            expected(case, server, "in", packet, client.getsockname(), "recvmsg")
        for client in reversed(clients):
            response = dns_packet(response=True)
            send_packets(server, [response], client.getsockname(), "sendmsg")
            expected(case, server, "out", response, client.getsockname(), "sendmsg")
            received, unused = receive_packets(client, "recvmsg")
            assert received == [response]
            expected(case, client, "in", response, server.getsockname(), "recvmsg")
        print("[COMM OK] {} same IP, different ports, responses B then A".format(case), flush=True)
    finally:
        for sock in [server] + clients:
            sock.close()


def main():
    for send_mode, recv_mode in (("sendto", "recvfrom"), ("sendmsg", "recvmsg"),
                                 ("sendmmsg", "recvmmsg")):
        suffix = "to" if send_mode == "sendto" else "msg" if send_mode == "sendmsg" else "mmsg"
        for family, prefix in ((socket.AF_INET, "u4"), (socket.AF_INET6, "u6")):
            run_case(prefix + "_" + suffix, family, send_mode, recv_mode,
                     count=2 if send_mode == "sendmmsg" else 1)
    run_case("dual_msg", socket.AF_INET6, "sendmsg", "recvmsg", dual=True)
    run_case("dual_mmsg", socket.AF_INET6, "sendmmsg", "recvmmsg", dual=True, count=2)
    for send_mode, recv_mode in (("sendto", "recvfrom"), ("sendmsg", "recvmsg"),
                                 ("sendmmsg", "recvmmsg")):
        suffix = "to" if send_mode == "sendto" else "msg" if send_mode == "sendmsg" else "mmsg"
        run_case("v6_24_" + suffix, socket.AF_INET6, send_mode, recv_mode,
                 capacity=24, send_length=24, count=2 if send_mode == "sendmmsg" else 1)
        run_case("v6_short_" + suffix, socket.AF_INET6, send_mode, recv_mode,
                 capacity=16, count=2 if send_mode == "sendmmsg" else 1)
    run_case("v4_short", socket.AF_INET, "sendmsg", "recvmsg", capacity=8)
    run_case("v4_noname", socket.AF_INET, "sendmsg", "recvmsg", with_name=False)
    run_case("v4_partial", socket.AF_INET, "sendmmsg", "recvmmsg", count=2, partial=True)
    run_case("v4_connzero", socket.AF_INET, "sendmsg", "recvmsg", connected=True, name_zero=True, capacity=0)
    run_case("v6_connzero", socket.AF_INET6, "sendmsg", "recvmsg", connected=True, name_zero=True, capacity=0)
    stale_remote_case()
    short_send_case()
    for mode in ("sendto", "sendmsg", "sendmmsg"):
        dual_send_ipv4_name(mode)
    peer_ports_case(socket.AF_INET)
    peer_ports_case(socket.AF_INET6)
    with open(sys.argv[1], "w") as output:
        json.dump(EXPECTATIONS, output, indent=2)
    print("[COMM OK] wrote {} expected tracer events".format(len(EXPECTATIONS)), flush=True)


if __name__ == "__main__":
    main()
```

### B. 地址、元数据及序号校验器

文件名：`verify_runtime.py`。

来源：`/home/jiping/deepflow/deepflow-1/udp-validation-20261119.bkcXBN/verify_runtime.py`。

SHA256：`7aa0031f603f089bf54e5ed2f56c19a52200efc34738f78465e596cc403d785e`。

```python
#!/usr/bin/env python3

import collections
import ipaddress
import json
import re
import sys


def events_from_log(path):
    callbacks = []
    dumps = []
    with open(path, errors="replace") as source:
        for line in source:
            if "UDP_PEER queue=" in line:
                values = dict(re.findall(r"(\w+)=([^\s]+)", line))
                if "txid" not in values:
                    continue
                for key in ("pid", "fd", "socket_id", "cap_seq", "cap_len", "syscall_len", "txid"):
                    values[key] = int(values[key])
                for endpoint in ("local", "remote"):
                    address, port = values[endpoint].rsplit(":", 1)
                    values[endpoint + "_ip"] = address
                    values[endpoint + "_port"] = int(port)
                callbacks.append(values)
            elif "[datadump] SEQ" in line:
                patterns = dict(pid=r" PID (\d+)", fd=r" FD (\d+)",
                                direction=r" DIR (\S+)", socket_id=r" SOCKET_ID (\d+)",
                                cap_seq=r" DATA_SEQ (\d+)", length=r" LEN (\d+)",
                                syscall_len=r" SYSCALL_LEN (\d+)",
                                source=r" SOURCE_FN (\w+)\(\d+\)", msg_num=r" MSG_NUM (\d+)")
                values = {}
                for key, pattern in patterns.items():
                    match = re.search(pattern, line)
                    if match is None:
                        break
                    values[key] = match.group(1) if key in ("direction", "source") else int(match.group(1))
                else:
                    dumps.append(values)
    return callbacks, dumps


def main():
    expected = json.load(open(sys.argv[1]))
    callbacks, dumps = events_from_log(sys.argv[2])
    callback_index = collections.defaultdict(list)
    dump_index = collections.defaultdict(list)
    for event in callbacks:
        callback_index[(event["pid"], event["fd"], event["direction"], event["txid"])].append(event)
    for event in dumps:
        dump_index[(event["pid"], event["fd"], event["direction"], event["socket_id"], event["cap_seq"])].append(event)
    failures = []
    passed_cases = collections.Counter()
    peer_groups = collections.defaultdict(list)
    for wanted in expected:
        case = wanted["case"]
        key = (wanted["pid"], wanted["fd"], wanted["direction"], wanted["txid"])
        matches = callback_index[key]
        if len(matches) != 1:
            failures.append("{} {} callback count={}".format(case, key, len(matches)))
            continue
        event = matches[0]
        errors = []
        if (event["cap_len"], event["syscall_len"]) != (wanted["length"], wanted["length"]):
            errors.append("lengths {} vs {}".format((event["cap_len"], event["syscall_len"]), wanted["length"]))
        if event["local_port"] != wanted["local_port"]:
            errors.append("local port mismatch")
        if not case.startswith("dual") and event["local_ip"] != wanted["local_ip"]:
            errors.append("local IP {} != {}".format(event["local_ip"], wanted["local_ip"]))
        if wanted["complete"]:
            if (event["remote_ip"], event["remote_port"]) != (wanted["remote_ip"], wanted["remote_port"]):
                errors.append("remote {}:{} != {}:{}".format(event["remote_ip"], event["remote_port"], wanted["remote_ip"], wanted["remote_port"]))
        elif event["remote_port"] != 0 or not ipaddress.ip_address(event["remote_ip"]).is_unspecified:
            errors.append("truncated/null sockaddr reused remote {}:{}".format(event["remote_ip"], event["remote_port"]))
        dump_key = (event["pid"], event["fd"], event["direction"], event["socket_id"], event["cap_seq"])
        dump_matches = dump_index[dump_key]
        matching_dump = [dump for dump in dump_matches if dump["source"] == wanted["source"] and dump["msg_num"] == wanted["msg_num"]]
        if not matching_dump:
            errors.append("missing datadump source={} MSG_NUM={} (found {})".format(wanted["source"], wanted["msg_num"], dump_matches))
        elif matching_dump[0]["syscall_len"] != wanted["length"]:
            errors.append("datadump syscall_len mismatch")
        if errors:
            failures.append("{} {} {}".format(case, key, "; ".join(errors)))
        else:
            passed_cases[case] += 1
        if case.endswith("peerports") and wanted["local_port"] == 53053:
            peer_groups[(case, wanted["remote_port"])].append(event)
        if wanted["source"] == "sendmmsg" and wanted["msg_num"] == 2:
            peer_groups[(case + "_sendmmsg", wanted["fd"])].append(event)
    for (case, port), events in sorted(peer_groups.items()):
        socket_ids = {event["socket_id"] for event in events}
        sequences = sorted(event["cap_seq"] for event in events)
        if len(socket_ids) != 1 or sequences != [0, 1]:
            failures.append("{} endpoint={} ids={} sequences={}".format(case, port, socket_ids, sequences))
        else:
            print("[PEER OK] {} endpoint={} socket_id={} seq={}".format(case, port, next(iter(socket_ids)), sequences))
    for case in ("u4_peerports", "u6_peerports"):
        identities = [events[0]["socket_id"] for (group, port), events in peer_groups.items() if group == case]
        if len(identities) != 2 or len(set(identities)) != 2:
            failures.append("{} peers did not get two distinct IDs: {}".format(case, identities))
    for case, count in sorted(passed_cases.items()):
        print("[EVENT OK] {} {} events".format(case, count))
    if failures:
        for failure in failures:
            print("[FAIL] " + failure)
        print("[FAIL] {} of {} expected events; {} failures".format(sum(passed_cases.values()), len(expected), len(failures)))
        return 1
    print("[OK] {} events verified: tuples, callback lengths, SOURCE_FN, MSG_NUM, sendmmsg and peer-port sequences".format(len(expected)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### C. 双 peer 服务端

文件名：`udp_peer_server.c`。

来源：`agent/src/ebpf/test/udp-peer-id/udp_peer_server.c（测试 HEAD）`。

SHA256：`bbf70b8937569d29f8daa185047720c11ee1bb7163651b7be4f3b65450f2b256`。

```c
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_BIND_IP "127.0.0.1"
#define DEFAULT_PORT 53053
#define MESSAGE_COUNT 2
#define BUFFER_SIZE 512

struct received_message {
	uint8_t data[BUFFER_SIZE];
	ssize_t len;
	struct sockaddr_in peer;
	socklen_t peer_len;
};

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static uint16_t parse_port(const char *text)
{
	char *end = NULL;
	long value = strtol(text, &end, 10);

	if (end == text || *end != '\0' || value <= 0 || value > 65535) {
		fprintf(stderr, "invalid port: %s\n", text);
		exit(EXIT_FAILURE);
	}
	return (uint16_t)value;
}

static void format_peer(const struct sockaddr_in *peer, char *ip, size_t ip_len)
{
	if (inet_ntop(AF_INET, &peer->sin_addr, ip, ip_len) == NULL)
		die("inet_ntop");
}

int main(int argc, char **argv)
{
	const char *bind_ip = argc > 1 ? argv[1] : DEFAULT_BIND_IP;
	uint16_t port = argc > 2 ? parse_port(argv[2]) : DEFAULT_PORT;
	struct sockaddr_in local = {0};
	struct received_message messages[MESSAGE_COUNT];
	int fd;
	int one = 1;

	memset(messages, 0, sizeof(messages));
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		die("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("setsockopt");

	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	if (inet_pton(AF_INET, bind_ip, &local.sin_addr) != 1) {
		fprintf(stderr, "invalid bind address: %s\n", bind_ip);
		return EXIT_FAILURE;
	}
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		die("bind");

	printf("server fd=%d listening on %s:%u\n", fd, bind_ip, port);
	fflush(stdout);

	for (int i = 0; i < MESSAGE_COUNT; i++) {
		char peer_ip[INET_ADDRSTRLEN];

		messages[i].peer_len = sizeof(messages[i].peer);
		messages[i].len = recvfrom(fd, messages[i].data,
					    sizeof(messages[i].data), 0,
					    (struct sockaddr *)&messages[i].peer,
					    &messages[i].peer_len);
		if (messages[i].len < 0)
			die("recvfrom");
		if (messages[i].len < 12) {
			fprintf(stderr, "DNS message is too short: %zd\n",
				messages[i].len);
			return EXIT_FAILURE;
		}
		format_peer(&messages[i].peer, peer_ip, sizeof(peer_ip));
		printf("received id=0x%02x%02x from %s:%u on fd=%d\n",
		       messages[i].data[0], messages[i].data[1], peer_ip,
		       ntohs(messages[i].peer.sin_port), fd);
	}

	/* Reply to B before A to exercise interleaved peer ordering. */
	for (int i = MESSAGE_COUNT - 1; i >= 0; i--) {
		char peer_ip[INET_ADDRSTRLEN];
		ssize_t sent;

		messages[i].data[2] = 0x81;
		messages[i].data[3] = 0x80;
		sent = sendto(fd, messages[i].data, (size_t)messages[i].len, 0,
			      (struct sockaddr *)&messages[i].peer,
			      messages[i].peer_len);
		if (sent != messages[i].len)
			die("sendto");
		format_peer(&messages[i].peer, peer_ip, sizeof(peer_ip));
		printf("replied id=0x%02x%02x to %s:%u on fd=%d\n",
		       messages[i].data[0], messages[i].data[1], peer_ip,
		       ntohs(messages[i].peer.sin_port), fd);
	}

	if (close(fd) < 0)
		die("close");
	return EXIT_SUCCESS;
}
```

### D. 双 peer 客户端

文件名：`udp_peer_client.c`。

来源：`agent/src/ebpf/test/udp-peer-id/udp_peer_client.c（测试 HEAD）`。

SHA256：`26d96ec95bb2534800050e2674d288d1687f9523c73fade77f50417d3d3a368b`。

```c
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_PORT 53053
#define CLIENT_COUNT 2

static const uint8_t dns_query_template[] = {
	0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 'a',  0x04, 't',
	'e',  's',  't',  0x00, 0x00, 0x01, 0x00, 0x01,
};

static void die(const char *message)
{
	perror(message);
	exit(EXIT_FAILURE);
}

static uint16_t parse_port(const char *text)
{
	char *end = NULL;
	long value = strtol(text, &end, 10);

	if (end == text || *end != '\0' || value <= 0 || value > 65535) {
		fprintf(stderr, "invalid port: %s\n", text);
		exit(EXIT_FAILURE);
	}
	return (uint16_t)value;
}

static int create_client(const char *local_ip)
{
	struct sockaddr_in local = {0};
	struct sockaddr_in actual = {0};
	socklen_t actual_len = sizeof(actual);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket");
	local.sin_family = AF_INET;
	if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1) {
		fprintf(stderr, "invalid local address: %s\n", local_ip);
		exit(EXIT_FAILURE);
	}
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		die("bind");
	if (getsockname(fd, (struct sockaddr *)&actual, &actual_len) < 0)
		die("getsockname");
	printf("client fd=%d bound to %s:%u\n", fd, local_ip,
	       ntohs(actual.sin_port));
	return fd;
}

static void send_query(int fd, const struct sockaddr_in *server, uint16_t id)
{
	uint8_t query[sizeof(dns_query_template)];
	ssize_t sent;

	memcpy(query, dns_query_template, sizeof(query));
	query[0] = (uint8_t)(id >> 8);
	query[1] = (uint8_t)id;
	sent = sendto(fd, query, sizeof(query), 0,
		      (const struct sockaddr *)server, sizeof(*server));
	if (sent != (ssize_t)sizeof(query))
		die("sendto");
	printf("sent id=0x%04x on fd=%d\n", id, fd);
}

static void receive_response(int fd, uint16_t expected_id)
{
	char peer_ip[INET_ADDRSTRLEN];
	uint8_t response[512];
	struct sockaddr_in peer = {0};
	socklen_t peer_len = sizeof(peer);
	ssize_t received =
	    recvfrom(fd, response, sizeof(response), 0,
		     (struct sockaddr *)&peer, &peer_len);
	uint16_t id;

	if (received < 0)
		die("recvfrom");
	if (peer.sin_family != AF_INET) {
		fprintf(stderr, "unexpected response address family: %u\n",
			(unsigned int)peer.sin_family);
		exit(EXIT_FAILURE);
	}
	if (inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip)) == NULL)
		die("inet_ntop");
	if (received < 12) {
		fprintf(stderr, "DNS response is too short: %zd\n", received);
		exit(EXIT_FAILURE);
	}
	id = (uint16_t)((uint16_t)response[0] << 8 | response[1]);
	if (id != expected_id || (response[2] & 0x80) == 0) {
		fprintf(stderr, "unexpected DNS response id=0x%04x\n", id);
		exit(EXIT_FAILURE);
	}
	printf("received response id=0x%04x from %s:%u on fd=%d\n", id,
	       peer_ip, ntohs(peer.sin_port), fd);
}

int main(int argc, char **argv)
{
	const char *server_ip = argc > 1 ? argv[1] : DEFAULT_SERVER_IP;
	uint16_t port = argc > 2 ? parse_port(argv[2]) : DEFAULT_PORT;
	const char *local_ips[CLIENT_COUNT] = {"127.0.0.2", "127.0.0.3"};
	const uint16_t ids[CLIENT_COUNT] = {0x1111, 0x2222};
	struct sockaddr_in server = {0};
	int fds[CLIENT_COUNT];

	server.sin_family = AF_INET;
	server.sin_port = htons(port);
	if (inet_pton(AF_INET, server_ip, &server.sin_addr) != 1) {
		fprintf(stderr, "invalid server address: %s\n", server_ip);
		return EXIT_FAILURE;
	}

	for (int i = 0; i < CLIENT_COUNT; i++)
		fds[i] = create_client(local_ips[i]);
	for (int i = 0; i < CLIENT_COUNT; i++)
		send_query(fds[i], &server, ids[i]);

	/* The server deliberately replies to B before A. */
	receive_response(fds[1], ids[1]);
	receive_response(fds[0], ids[0]);

	for (int i = 0; i < CLIENT_COUNT; i++) {
		if (close(fds[i]) < 0)
			die("close");
	}
	return EXIT_SUCCESS;
}
```

### E. 双 peer 隔离校验器

文件名：`verify_socket_tracer.py`。

来源：`agent/src/ebpf/test/udp-peer-id/verify_socket_tracer.py（测试 HEAD）`。

SHA256：`d30c68202d7bcb2e9cb387b6f46c7517d618000be3ebb0af89c422bcd6c9069e`。

```python
#!/usr/bin/env python3

import re
import sys
from collections import defaultdict
from pathlib import Path


EVENT_PATTERN = re.compile(
    r"UDP_PEER .*?process=(?P<process>\S+) .*?fd=(?P<fd>\d+) "
    r"direction=(?P<direction>in|out) socket_id=(?P<socket_id>\d+) "
    r"cap_seq=(?P<cap_seq>\d+) local=(?P<local_ip>[^: ]+):(?P<local_port>\d+) "
    r"remote=(?P<remote_ip>[^: ]+):(?P<remote_port>\d+)"
)
EXPECTED_REMOTE_IPS = {"127.0.0.2", "127.0.0.3"}


def fail(message):
    print(f"[FAIL] {message}", file=sys.stderr)
    return 1


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} SOCKET_TRACER_LOG", file=sys.stderr)
        return 2

    events = defaultdict(list)
    for line in Path(sys.argv[1]).read_text(errors="replace").splitlines():
        match = EVENT_PATTERN.search(line)
        if match is None or match.group("process") != "udp_peer_server":
            continue
        event = match.groupdict()
        if event["remote_ip"] in EXPECTED_REMOTE_IPS:
            events[event["remote_ip"]].append(event)

    missing = EXPECTED_REMOTE_IPS - events.keys()
    if missing:
        return fail(f"missing server events for peers: {sorted(missing)}")

    peer_socket_ids = {}
    for remote_ip in sorted(EXPECTED_REMOTE_IPS):
        peer_events = events[remote_ip]
        socket_ids = {event["socket_id"] for event in peer_events}
        directions = {event["direction"] for event in peer_events}
        sequences = sorted(int(event["cap_seq"]) for event in peer_events)
        fds = {event["fd"] for event in peer_events}

        if len(socket_ids) != 1:
            return fail(f"peer {remote_ip} has multiple socket IDs: {socket_ids}")
        if directions != {"in", "out"}:
            return fail(f"peer {remote_ip} directions are {directions}, expected in/out")
        if sequences != [0, 1]:
            return fail(f"peer {remote_ip} cap_seq is {sequences}, expected [0, 1]")
        if len(fds) != 1:
            return fail(f"peer {remote_ip} uses multiple server FDs: {fds}")
        peer_socket_ids[remote_ip] = next(iter(socket_ids))

    if len(set(peer_socket_ids.values())) != len(EXPECTED_REMOTE_IPS):
        return fail(f"different peers share socket ID: {peer_socket_ids}")

    all_fds = {event["fd"] for peer_events in events.values() for event in peer_events}
    if len(all_fds) != 1:
        return fail(f"server peers do not share one physical FD: {all_fds}")

    print("[OK] UDP peer socket ID isolation")
    for remote_ip in sorted(EXPECTED_REMOTE_IPS):
        print(
            f"  peer={remote_ip} fd={next(iter(all_fds))} "
            f"socket_id={peer_socket_ids[remote_ip]} cap_seq=0,1"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### F. 宿主机测试编排与 Map 检查

文件名：`run_host_validation.py`。

来源：`/home/jiping/deepflow/deepflow-1/udp-validation-20261119.bkcXBN/run_host_validation.py`。

SHA256：`311c00a4ca79b3108df51d20fb9333a1c0e13d5c4eb466f4a265c94fa37a70a6`。

```python
#!/usr/bin/env python3

import ctypes
import json
import os
import struct
import subprocess
import sys
import time

from verify_runtime import events_from_log


ROOT = "/home/jiping/deepflow/deepflow-1/deepflow"
ARTIFACTS = os.path.dirname(os.path.realpath(__file__))
EBPF = os.path.join(ROOT, "agent/src/ebpf")
BINARY = os.path.join(ARTIFACTS, "socket_tracer")
PEER_DIR = os.path.join(EBPF, "test/udp-peer-id")
RESULTS = []


def snapshot_maps(enabled):
    libc = ctypes.CDLL(None, use_errno=True)
    attributes = (ctypes.c_uint * 4)()
    current_id = 0
    maps = []
    for unused in range(20000):
        attributes[0] = current_id
        attributes[1] = 0
        if libc.syscall(321, 12, ctypes.byref(attributes), ctypes.sizeof(attributes)) < 0:
            break
        current_id = attributes[1]
        get_fd = (ctypes.c_uint * 4)(current_id, 0, 0, 0)
        descriptor = libc.syscall(321, 14, ctypes.byref(get_fd), ctypes.sizeof(get_fd))
        if descriptor < 0:
            continue
        try:
            info = ctypes.create_string_buffer(256)
            request = struct.pack("IIQ", descriptor, len(info), ctypes.addressof(info))
            if libc.syscall(321, 15, request, len(request)) < 0:
                continue
            map_type, map_id, key_size, value_size, capacity, flags = struct.unpack("6I", info.raw[:24])
            name = info.raw[24:40].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            if "udp_peer" in name:
                maps.append(dict(name=name, id=map_id, type=map_type, key_size=key_size,
                                 value_size=value_size, capacity=capacity))
        finally:
            os.close(descriptor)
    mode = "enabled" if enabled else "disabled"
    with open(os.path.join(ARTIFACTS, "maps-" + mode + ".json"), "w") as output:
        json.dump(maps, output, indent=2)
    peer_maps = [entry for entry in maps if entry["name"] == "__udp_peer_map"]
    record("LRU map capacity " + mode,
           len(peer_maps) == 1 and peer_maps[0]["type"] == 9 and peer_maps[0]["capacity"] == (40960 if enabled else 1),
           str(maps))


def command(arguments, log_name, timeout=30):
    with open(os.path.join(ARTIFACTS, log_name), "w") as output:
        result = subprocess.run(arguments, stdout=output, stderr=subprocess.STDOUT,
                                timeout=timeout, env=dict(os.environ, LC_ALL="en_US.utf8"))
    return result.returncode


def start_tracer(enabled):
    mode = "enabled" if enabled else "disabled"
    path = os.path.join(ARTIFACTS, "tracer-" + mode + ".log")
    environment = dict(os.environ, UDP_TEST_PEER_ID="1" if enabled else "0",
                       UDP_TEST_LOG=os.path.join(ARTIFACTS, "ebpf-" + mode + ".log"),
                       RUST_LOG="info", LC_ALL="en_US.utf8")
    output = open(path, "w")
    process = subprocess.Popen([BINARY], stdout=output, stderr=subprocess.STDOUT,
                               cwd=ARTIFACTS, env=environment)
    with open(os.path.join(ARTIFACTS, "tracer-" + mode + ".pid"), "w") as pid_file:
        pid_file.write(str(process.pid))
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output.close()
            raise RuntimeError("tracer {} exited {}: {}".format(mode, process.returncode, path))
        with open(path, errors="replace") as source:
            text = source.read()
        if "Set current state: TRACER_RUNNING" in text or "Set the status to TRACER_RUNNING" in text:
            time.sleep(2)
            print("[READY] host tracer {} pid={}".format(mode, process.pid), flush=True)
            return process, output, path
        time.sleep(0.5)
    process.terminate()
    process.wait(timeout=10)
    output.close()
    raise RuntimeError("tracer readiness timeout: " + path)


def stop_tracer(process, output):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    output.close()
    print("[STOPPED] host tracer pid={}".format(process.pid), flush=True)


def peer_traffic(bind_ip, name):
    with open(os.path.join(ARTIFACTS, name + "-server.log"), "w") as output:
        server = subprocess.Popen([os.path.join(PEER_DIR, "udp_peer_server"), bind_ip, "53053"],
                                  stdout=output, stderr=subprocess.STDOUT)
        try:
            time.sleep(0.3)
            result = command([os.path.join(PEER_DIR, "udp_peer_client"), "127.0.0.1", "53053"],
                             name + "-client.log", timeout=10)
            assert result == 0, "peer client failed"
            assert server.wait(timeout=10) == 0, "peer server failed"
        finally:
            if server.poll() is None:
                server.kill()
                server.wait(timeout=5)
    time.sleep(1.5)


def log_segment(source_path, offset, destination_name):
    destination = os.path.join(ARTIFACTS, destination_name)
    with open(source_path, "rb") as source, open(destination, "wb") as output:
        source.seek(offset)
        output.write(source.read())
    return destination


def record(name, success, detail):
    RESULTS.append(dict(name=name, success=success, detail=detail))
    print("[{}] {}: {}".format("PASS" if success else "FAIL", name, detail), flush=True)


def check_physical_ids(path, name, wildcard=False):
    callbacks, unused = events_from_log(path)
    events = [event for event in callbacks if event["process"] == "udp_peer_server"
              and event["local_port"] == 53053]
    ids = {event["socket_id"] for event in events}
    sequences = sorted(event["cap_seq"] for event in events)
    endpoints = {event["remote_ip"] for event in events}
    success = len(events) == 4 and len(ids) == 1 and sequences == [0, 1, 2, 3] and endpoints == {"127.0.0.2", "127.0.0.3"}
    if wildcard:
        success = success and all(event["local_ip"] == "0.0.0.0" for event in events)
    record(name, success, "events={} IDs={} sequences={} peers={}".format(len(events), sorted(ids), sequences, sorted(endpoints)))


def main():
    process, output, log_path = start_tracer(True)
    try:
        snapshot_maps(True)
        offset = os.path.getsize(log_path)
        peer_traffic("127.0.0.1", "peer-enabled")
        peer_log = log_segment(log_path, offset, "peer-enabled.log")
        result = command([sys.executable, os.path.join(PEER_DIR, "verify_socket_tracer.py"), peer_log],
                         "peer-enabled-verification.log")
        record("IPv4 dual-peer A,B / B,A isolation", result == 0, "peer-enabled-verification.log")
        offset = os.path.getsize(log_path)
        expected = os.path.join(ARTIFACTS, "runtime-expectations.json")
        result = command([sys.executable, os.path.join(ARTIFACTS, "udp_syscall_cases.py"), expected],
                         "runtime-communication.log", timeout=60)
        record("UDP syscall communication", result == 0, "runtime-communication.log")
        time.sleep(3)
        syscall_log = log_segment(log_path, offset, "syscall-runtime.log")
        if result == 0:
            result = command([sys.executable, os.path.join(ARTIFACTS, "verify_runtime.py"), expected, syscall_log],
                             "runtime-verification.log")
            record("UDP syscall tuple/metadata and mmsg/peer-port isolation", result == 0, "runtime-verification.log")
        offset = os.path.getsize(log_path)
        peer_traffic("0.0.0.0", "peer-wildcard")
        fallback_log = log_segment(log_path, offset, "peer-wildcard.log")
        check_physical_ids(fallback_log, "Wildcard local-IP missing fallback", wildcard=True)
    finally:
        stop_tracer(process, output)
    process, output, log_path = start_tracer(False)
    try:
        snapshot_maps(False)
        offset = os.path.getsize(log_path)
        peer_traffic("127.0.0.1", "peer-disabled")
        baseline_log = log_segment(log_path, offset, "peer-disabled.log")
        check_physical_ids(baseline_log, "Feature disabled physical IDs")
        result = command([sys.executable, os.path.join(PEER_DIR, "verify_socket_tracer.py"), baseline_log],
                         "peer-disabled-negative-verification.log")
        record("Isolation verifier rejects disabled feature", result != 0, "peer-disabled-negative-verification.log")
    finally:
        stop_tracer(process, output)
    with open(os.path.join(ARTIFACTS, "runtime-results.json"), "w") as result_file:
        json.dump(RESULTS, result_file, indent=2)
    return 0 if all(result["success"] for result in RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
```

### G. C 测试程序构建文件

文件名：`Makefile`。

来源：`agent/src/ebpf/test/udp-peer-id/Makefile（测试 HEAD）`。

SHA256：`8f43fa53d15f75c62839bf5a3918b27d00240df6ce848585a1451d7e1896b009`。

```makefile
CC ?= gcc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror

TARGETS := udp_peer_client udp_peer_server

.PHONY: all clean

all: $(TARGETS)

udp_peer_client: udp_peer_client.c
	$(CC) $(CFLAGS) $< -o $@

udp_peer_server: udp_peer_server.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)
```

### H. 实际测试的 Rust socket_tracer 采集程序

文件名：`main.rs.test-instrumented`。

来源：`/home/jiping/deepflow/deepflow-1/udp-validation-20261119.bkcXBN/main.rs.test-instrumented`。

SHA256：`81a6ac284a88f4f9958a3901c15eb6e69e25ba1eba734556dd28573f3e459d88`。

本代码块仅移除原采集源码的一处行尾空格，不改变逻辑；归档原文件 SHA256 为
`feb0deb1777ba6faa4c117f89da5b32c3da0f109d4c4e771a0338da5c795cb00`。

```rust
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

use chrono::prelude::DateTime;
use chrono::FixedOffset;
use chrono::Utc;
use log::info;
use socket_tracer::ebpf::*;
use std::convert::TryInto;
use std::env;
use std::ffi::CString;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

extern "C" {
    fn print_uprobe_http2_info(data: *mut c_char, len: c_uint);
    fn print_uprobe_grpc_dataframe(data: *mut c_char, len: c_uint);
    fn print_io_event_info(data: *mut c_char, len: c_uint);
}

lazy_static::lazy_static! {
    static ref SUM: Mutex<u32> = Mutex::new(0);
}

lazy_static::lazy_static! {
    static ref COUNTER: Mutex<u32> = Mutex::new(0);
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct HookedSocketSyscallBitmap(c_ulonglong);

impl HookedSocketSyscallBitmap {
    fn set_enabled(&mut self, bit: c_ulonglong) {
        self.0 |= bit;
    }
}

impl<T: AsRef<str>> From<&[T]> for HookedSocketSyscallBitmap {
    fn from(vs: &[T]) -> Self {
        let mut bitmap = HookedSocketSyscallBitmap(0);
        for v in vs.iter() {
            match v.as_ref() {
                "read" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_READ),
                "readv" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_READV),
                "recvfrom" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_RECVFROM),
                "recvmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_RECVMSG),
                "recvmmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_RECVMMSG),
                "sendmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_SENDMSG),
                "sendmmsg" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_SENDMMSG),
                "sendto" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_SENDTO),
                "write" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_WRITE),
                "writev" => bitmap.set_enabled(HOOKED_SOCKET_SYSCALL_WRITEV),
                _ => {}
            }
        }
        bitmap
    }
}

const HOOKED_SOCKET_SYSCALL_READ: c_ulonglong = 1 << 0;
const HOOKED_SOCKET_SYSCALL_READV: c_ulonglong = 1 << 1;
const HOOKED_SOCKET_SYSCALL_RECVFROM: c_ulonglong = 1 << 2;
const HOOKED_SOCKET_SYSCALL_RECVMSG: c_ulonglong = 1 << 3;
const HOOKED_SOCKET_SYSCALL_RECVMMSG: c_ulonglong = 1 << 4;
const HOOKED_SOCKET_SYSCALL_SENDMSG: c_ulonglong = 1 << 5;
const HOOKED_SOCKET_SYSCALL_SENDMMSG: c_ulonglong = 1 << 6;
const HOOKED_SOCKET_SYSCALL_SENDTO: c_ulonglong = 1 << 7;
const HOOKED_SOCKET_SYSCALL_WRITE: c_ulonglong = 1 << 8;
const HOOKED_SOCKET_SYSCALL_WRITEV: c_ulonglong = 1 << 9;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hooked_socket_syscall_bitmap_sets_expected_bits() {
        let syscalls = ["read", "recvfrom", "sendto", "write"];
        let bitmap = HookedSocketSyscallBitmap::from(syscalls.as_slice());

        assert_eq!(
            bitmap,
            HookedSocketSyscallBitmap(
                HOOKED_SOCKET_SYSCALL_READ
                    | HOOKED_SOCKET_SYSCALL_RECVFROM
                    | HOOKED_SOCKET_SYSCALL_SENDTO
                    | HOOKED_SOCKET_SYSCALL_WRITE,
            ),
        );
    }

    #[test]
    fn set_hooked_socket_syscalls_accepts_bitmap_from_syscall_names() {
        let syscalls = ["write", "read", "write", "sendto"];
        let bitmap = HookedSocketSyscallBitmap::from(syscalls.as_slice());

        assert_eq!(
            bitmap,
            HookedSocketSyscallBitmap(
                HOOKED_SOCKET_SYSCALL_READ
                    | HOOKED_SOCKET_SYSCALL_SENDTO
                    | HOOKED_SOCKET_SYSCALL_WRITE,
            ),
        );

        unsafe {
            set_hooked_socket_syscalls(bitmap.0);
        }
    }
}

#[allow(dead_code)]
fn increment_counter(num: u32, counter_type: u32) {
    if counter_type == 0 {
        let mut counter = COUNTER.lock().unwrap();
        *counter += num;
    } else {
        let mut counter = SUM.lock().unwrap();
        *counter += num;
    }
}

fn flow_info(sd: *mut SK_BPF_DATA) -> String {
    unsafe {
        let mut flow = String::from("");
        if (*sd).direction == SOCK_DIR_SND {
            write!(
                flow,
                "{} {}.{} > {}.{}",
                sk_l4proto_safe(sd),
                sk_laddr_str_safe(sd),
                (*sd).tuple.lport,
                sk_raddr_str_safe(sd),
                (*sd).tuple.rport
            )
            .unwrap();
        } else {
            write!(
                flow,
                "{} {}.{} > {}.{}",
                sk_l4proto_safe(sd),
                sk_raddr_str_safe(sd),
                (*sd).tuple.rport,
                sk_laddr_str_safe(sd),
                (*sd).tuple.lport
            )
            .unwrap();
        }

        return flow;
    }
}

fn date_time(ts: u64) -> String {
    // Creates a new SystemTime from the specified number of whole seconds
    let d = UNIX_EPOCH + Duration::from_nanos(ts);
    // Create DateTime from SystemTime
    let time = DateTime::<Utc>::from(d);
    let china_timezone = FixedOffset::east(8 * 3600);
    // Formats the combined date and time with the specified format string.
    time.with_timezone(&china_timezone)
        .format("%Y-%m-%d %H:%M:%S.%6f")
        .to_string()
}

fn sk_str_safe(data: *mut c_char) -> String {
    unsafe { CStr::from_ptr(data).to_string_lossy().into_owned() }
}

fn sk_bytes(data: *mut c_char, len: u32) -> &'static [u8] {
    unsafe {
        let slice = std::slice::from_raw_parts(data, len as usize);
        &*(slice as *const [c_char] as *const [u8])
    }
}

fn sk_bytes_safe(data: *mut c_char, len: u32) -> Vec<u8> {
    sk_bytes(data, len).iter().cloned().collect()
}

fn sk_data_str_safe(sd: *mut SK_BPF_DATA) -> String {
    unsafe { sk_str_safe((*sd).cap_data) }
}

fn sk_data_bytes_safe(sd: *mut SK_BPF_DATA) -> Vec<u8> {
    unsafe { sk_bytes_safe((*sd).cap_data, (*sd).cap_len) }
}

fn sk_proto_safe(sd: *mut SK_BPF_DATA) -> u16 {
    unsafe { (*sd).l7_protocol_hint }
}

//>= Rust 1.34
fn pop_4(barry: &[u8]) -> [u8; 4] {
    barry.try_into().expect("slice with incorrect length")
}

fn sk_ip_string_safe(addr: [u8; 16usize], addr_len: u8) -> String {
    let ret: String = String::from("");
    if addr_len == 4 {
        return IpAddr::from(pop_4(&addr[0..4])).to_string();
    } else if addr_len == 16 {
        return IpAddr::from(addr).to_string();
    }

    return ret;
}

fn sk_raddr_str_safe(sd: *mut SK_BPF_DATA) -> String {
    unsafe { sk_ip_string_safe((*sd).tuple.raddr, (*sd).tuple.addr_len) }
}

fn sk_laddr_str_safe(sd: *mut SK_BPF_DATA) -> String {
    unsafe { sk_ip_string_safe((*sd).tuple.laddr, (*sd).tuple.addr_len) }
}

fn sk_l4proto_safe(sd: *mut SK_BPF_DATA) -> &'static str {
    unsafe {
        if (*sd).tuple.protocol == 6 {
            return "TCP";
        } else if (*sd).tuple.protocol == 17 {
            return "UDP";
        }

        return "";
    }
}

fn process_name_safe(sd: *mut SK_BPF_DATA) -> String {
    unsafe {
        let v = &(*sd).process_kname;
        let len = v.iter().position(|&byte| byte == 0).unwrap_or(v.len());
        String::from_utf8_lossy(&v[..len]).into_owned()
    }
}

fn sd_container_id_safe(sd: *mut SK_BPF_DATA) -> String {
    unsafe {
        let v = &(*sd).container_id;
        String::from_utf8_lossy(v).to_string()
    }
}

#[allow(dead_code)]
extern "C" fn debug_callback(_data: *mut c_char, len: c_int) {
    // Ensure the input data is not null
    if _data.is_null() {
        return;
    }

    unsafe {
        let data_slice = std::slice::from_raw_parts(_data as *const u8, len as usize);
        println!("+ --------------- datadump --------------- +");
        println!("{}", String::from_utf8_lossy(data_slice));
        println!("+ ---------------------------------------- +");
    }
}

extern "C" fn socket_trace_callback(
    _: *mut c_void,
    queue_id: c_int,
    sd: *mut SK_BPF_DATA,
) -> c_int {
    if sd.is_null() {
        return 0;
    }

    unsafe {
        let event = &*sd;
        if event.tuple.protocol == 17 {
            let direction = if event.direction == SOCK_DIR_SND {
                "out"
            } else {
                "in"
            };
            println!(
                "UDP_PEER queue={} process={} pid={} fd={} direction={} socket_id={} cap_seq={} local={}:{} remote={}:{} cap_len={} syscall_len={} txid={}",
                queue_id,
                process_name_safe(sd),
                event.process_id,
                event.fd,
                direction,
                event.socket_id,
                event.cap_seq,
                sk_laddr_str_safe(sd),
                event.tuple.lport,
                sk_raddr_str_safe(sd),
                event.tuple.rport,
                event.cap_len,
                event.syscall_len,
                if event.cap_len >= 2 {
                    u16::from_be_bytes([
                        *(event.cap_data as *const u8),
                        *((event.cap_data as *const u8).add(1)),
                    ])
                } else {
                    0
                },
            );
        }

        let mut proto_tag = String::from("");
        if sk_proto_safe(sd) == SOCK_DATA_OTHER {
            proto_tag.push_str("ORTHER");
        } else if sk_proto_safe(sd) == SOCK_DATA_HTTP1 {
            proto_tag.push_str("HTTP1");
        } else if sk_proto_safe(sd) == SOCK_DATA_HTTP2 {
            proto_tag.push_str("HTTP2");
        } else if sk_proto_safe(sd) == SOCK_DATA_DNS {
            proto_tag.push_str("DNS");
        } else if sk_proto_safe(sd) == SOCK_DATA_MYSQL {
            proto_tag.push_str("MYSQL");
        } else if sk_proto_safe(sd) == SOCK_DATA_POSTGRESQL {
            proto_tag.push_str("POSTGRESQL");
        } else if sk_proto_safe(sd) == SOCK_DATA_REDIS {
            proto_tag.push_str("REDIS");
        } else if sk_proto_safe(sd) == SOCK_DATA_KAFKA {
            proto_tag.push_str("KAFKA");
        } else if sk_proto_safe(sd) == SOCK_DATA_MQTT {
            proto_tag.push_str("MQTT");
        } else if sk_proto_safe(sd) == SOCK_DATA_AMQP {
            proto_tag.push_str("AMQP");
        } else if sk_proto_safe(sd) == SOCK_DATA_NATS {
            proto_tag.push_str("NATS");
        } else if sk_proto_safe(sd) == SOCK_DATA_PULSAR {
            proto_tag.push_str("PULSAR");
        } else if sk_proto_safe(sd) == SOCK_DATA_DUBBO {
            proto_tag.push_str("DUBBO");
        } else if sk_proto_safe(sd) == SOCK_DATA_SOFARPC {
            proto_tag.push_str("SOFARPC");
        } else if sk_proto_safe(sd) == SOCK_DATA_FASTCGI {
            proto_tag.push_str("FASTCGI");
        } else if sk_proto_safe(sd) == SOCK_DATA_BRPC {
            proto_tag.push_str("BRPC");
        } else if sk_proto_safe(sd) == SOCK_DATA_TARS {
            proto_tag.push_str("TARS");
        } else if sk_proto_safe(sd) == SOCK_DATA_SOME_IP {
            proto_tag.push_str("SomeIP");
        } else if sk_proto_safe(sd) == SOCK_DATA_ISO8583 {
            proto_tag.push_str("ISO8583");
        } else if sk_proto_safe(sd) == SOCK_DATA_MONGO {
            proto_tag.push_str("MONGO");
        } else if sk_proto_safe(sd) == SOCK_DATA_TLS {
            proto_tag.push_str("TLS");
        } else if sk_proto_safe(sd) == SOCK_DATA_ORACLE {
            proto_tag.push_str("ORACLE");
        } else if sk_proto_safe(sd) == SOCK_DATA_SQL_SERVER {
            proto_tag.push_str("SQLSERVER");
        } else if sk_proto_safe(sd) == SOCK_DATA_OPENWIRE {
            proto_tag.push_str("OPENWIRE");
        } else if sk_proto_safe(sd) == SOCK_DATA_ZMTP {
            proto_tag.push_str("ZMTP");
        } else if sk_proto_safe(sd) == SOCK_DATA_WEBSPHEREMQ {
            proto_tag.push_str("WEBSPHEREMQ");
        } else {
            proto_tag.push_str("UNSPEC");
        }

        println!("+ --------------------------------- +");
        if sk_proto_safe(sd) == SOCK_DATA_HTTP1 {
            let data = sk_data_str_safe(sd);
            println!("{} <{}> BATCHLAST {} DIR {} TYPE {} PID {} THREAD_ID {} COROUTINE_ID {} CONTAINER_ID {} SOURCE {} ROLE {} COMM {} {} LEN {} SYSCALL_LEN {} SOCKET_ID 0x{:x} TRACE_ID 0x{:x} TCP_SEQ {} DATA_SEQ {} TLS {} TimeStamp {}\n{}",
                     date_time((*sd).timestamp),
                     proto_tag,
                     (*sd).batch_last_data,
                     (*sd).direction,
                     (*sd).msg_type,
                     (*sd).process_id,
                     (*sd).thread_id,
                     (*sd).coroutine_id,
                     sd_container_id_safe(sd),
                     (*sd).source,
                     (*sd).socket_role,
                     process_name_safe(sd),
                     flow_info(sd),
                     (*sd).cap_len,
                     (*sd).syscall_len,
                     (*sd).socket_id,
                     (*sd).syscall_trace_id_call,
                     (*sd).tcp_seq,
                     (*sd).cap_seq,
                     (*sd).is_tls,
                     (*sd).timestamp,
                     data);
        } else {
            let data: Vec<u8> = sk_data_bytes_safe(sd);
            println!("{} <{}> BATCHLAST {} DIR {} TYPE {} PID {} THREAD_ID {} COROUTINE_ID {} CONTAINER_ID {} SOURCE {} ROLE {} COMM {} {} LEN {} SYSCALL_LEN {} SOCKET_ID 0x{:x} TRACE_ID 0x{:x} TCP_SEQ {} DATA_SEQ {} TLS {} TimeStamp {}",
                     date_time((*sd).timestamp),
                     proto_tag,
                     (*sd).batch_last_data,
                     (*sd).direction,
                     (*sd).msg_type,
                     (*sd).process_id,
                     (*sd).thread_id,
                     (*sd).coroutine_id,
                     sd_container_id_safe(sd),
                     (*sd).source,
                     (*sd).socket_role,
                     process_name_safe(sd),
                     flow_info(sd),
                     (*sd).cap_len,
                     (*sd).syscall_len,
                     (*sd).socket_id,
                     (*sd).syscall_trace_id_call,
                     (*sd).tcp_seq,
                     (*sd).cap_seq,
                     (*sd).is_tls,
                     (*sd).timestamp);
            if (*sd).source == 2 {
                print_uprobe_http2_info((*sd).cap_data, (*sd).cap_len);
            } else if (*sd).source == 4 {
                print_io_event_info((*sd).cap_data, (*sd).cap_len);
            } else if (*sd).source == 5 {
                print_uprobe_grpc_dataframe((*sd).cap_data, (*sd).cap_len);
            } else if sk_proto_safe(sd) == SOCK_DATA_OTHER {
                for x in data.into_iter() {
                    print!("{} ", format!("{:02x}", x));
                }
            } else {
                for x in data.into_iter() {
                    if x < 32 || x > 126 {
                        print!(".");
                        continue;
                    }
                    let b = x as char;
                    print!("{0}", b);
                }
            }
            print!("\x1b[0m\n");
        }

        println!("+ --------------------------------- +\n");
    }

    0
}

#[allow(dead_code)]
extern "C" fn process_event_handle(p: *mut PROCESS_EVENT) {
    unsafe {
        println!(
            "TYPE {} PID {} NAME {}",
            (*p).event_type,
            (*p).pid,
            String::from_utf8_lossy(&(*p).name).to_string()
        );
    }
}

#[allow(dead_code)]
fn cp_data_str_safe(cp: *mut stack_profile_data) -> String {
    unsafe { sk_str_safe((*cp).stack_data) }
}

#[allow(dead_code)]
fn cp_process_name_safe(cp: *mut stack_profile_data) -> String {
    unsafe {
        let v = &(*cp).comm;
        String::from_utf8_lossy(v).to_string()
    }
}

#[allow(dead_code)]
extern "C" fn continuous_profiler_callback(cp: *mut stack_profile_data) {
    unsafe {
        //process_stack_trace_data_for_flame_graph(cp);
        //increment_counter((*cp).count, 1);
        //increment_counter(1, 0);
        //let data = cp_data_str_safe(cp);
        //println!("\n+ --------------------------------- +");
        //println!("{} PID {} START-TIME {} NETNS-ID {} U-STACKID {} K-STACKID {} COMM {} CPU {} COUNT {} LEN {} \n  - {}",
        //           date_time((*cp).timestamp / 1000),
        //           (*cp).pid,
        //           (*cp).stime,
        //           (*cp).netns_id,
        //           (*cp).u_stack_id,
        //           (*cp).k_stack_id,
        //           cp_process_name_safe(cp),
        //           (*cp).cpu,
        //           (*cp).count,
        //           (*cp).stack_data_len, data);
        //println!("+ --------------------------------- +");
    }
}

#[allow(dead_code)]
fn get_counter(counter_type: u32) -> u32 {
    if counter_type == 0 {
        *COUNTER.lock().unwrap()
    } else {
        *SUM.lock().unwrap()
    }
}

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    env_logger::builder()
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis))
        .init();

    let log_file = CString::new(env::var("UDP_TEST_LOG").unwrap_or_else(|_| "/var/log/deepflow-ebpf.log".to_string())).unwrap();
    let log_file_c = log_file.as_c_str();
    match trace_utils::protect_cpu_affinity() {
        Ok(()) => info!("CPU affinity protected successfully"),
        Err(e) => {
            // Distinguish between "numad not found" (normal) and other errors
            if e.kind() == std::io::ErrorKind::NotFound {
                println!("numad process not found, skipping CPU affinity protection (normal)");
            } else {
                println!(
                    "Failed to protect CPU affinity due to unexpected error: {}",
                    e
                );
            }
        }
    }
    unsafe {
        enable_ebpf_protocol(SOCK_DATA_HTTP1 as c_int);
        enable_ebpf_protocol(SOCK_DATA_HTTP2 as c_int);
        enable_ebpf_protocol(SOCK_DATA_DUBBO as c_int);
        enable_ebpf_protocol(SOCK_DATA_SOFARPC as c_int);
        enable_ebpf_protocol(SOCK_DATA_FASTCGI as c_int);
        enable_ebpf_protocol(SOCK_DATA_BRPC as c_int);
        enable_ebpf_protocol(SOCK_DATA_TARS as c_int);
        enable_ebpf_protocol(SOCK_DATA_SOME_IP as c_int);
        enable_ebpf_protocol(SOCK_DATA_ISO8583 as c_int);
        enable_ebpf_protocol(SOCK_DATA_MYSQL as c_int);
        enable_ebpf_protocol(SOCK_DATA_POSTGRESQL as c_int);
        enable_ebpf_protocol(SOCK_DATA_REDIS as c_int);
        enable_ebpf_protocol(SOCK_DATA_KAFKA as c_int);
        enable_ebpf_protocol(SOCK_DATA_MQTT as c_int);
        enable_ebpf_protocol(SOCK_DATA_AMQP as c_int);
        enable_ebpf_protocol(SOCK_DATA_OPENWIRE as c_int);
        enable_ebpf_protocol(SOCK_DATA_ZMTP as c_int);
        enable_ebpf_protocol(SOCK_DATA_WEBSPHEREMQ as c_int);
        enable_ebpf_protocol(SOCK_DATA_NATS as c_int);
        enable_ebpf_protocol(SOCK_DATA_PULSAR as c_int);
        enable_ebpf_protocol(SOCK_DATA_DNS as c_int);
        enable_ebpf_protocol(SOCK_DATA_MONGO as c_int);
        enable_ebpf_protocol(SOCK_DATA_TLS as c_int);

        //set_feature_regex(
        //    FEATURE_UPROBE_OPENSSL,
        //    CString::new(".*".as_bytes()).unwrap().as_c_str().as_ptr(),
        //);
        //set_feature_regex(
        //    FEATURE_UPROBE_GOLANG,
        //    CString::new(".*".as_bytes()).unwrap().as_c_str().as_ptr(),
        //);

        //set_io_event_collect_mode(1);

        //set_io_event_minimal_duration(1000000);

        //// enable go auto traceing,
        //set_go_tracing_timeout(120);

        /*
            let bypass_port = 443;
            let mut bypass_port_bitmap: [u8; 65536 / 8] = [0; 65536 / 8];
            bypass_port_bitmap[bypass_port / 8] |= 1 << (bypass_port % 8);
            set_bypass_port_bitmap(bypass_port_bitmap.as_ptr());

            let allow_port = 443;
            let mut allow_port_bitmap: [u8; 65536 / 8] = [0; 65536 / 8];
            allow_port_bitmap[allow_port / 8] |= 1 << (allow_port % 8);
            set_allow_port_bitmap(allow_port_bitmap.as_ptr());
        */

        // Capture application data exchanged over Unix domain sockets.
        // This must be enabled before the socket tracer is initialized.
        enable_unix_socket_feature();

        // The first parameter passed by a null pointer can be
        // filled with std::ptr::null()
        if bpf_tracer_init(log_file_c.as_ptr(), true) != 0 {
            println!("bpf_tracer_init() file:{:?} error", log_file);
            ::std::process::exit(1);
        }
        /*
                if register_event_handle(
                    EVENT_TYPE_PROC_EXEC | EVENT_TYPE_PROC_EXIT,
                    process_event_handle,
                ) != 0
                {
                    println!("register_event_handle() faild");
                    ::std::process::exit(1);
                }
        */

        set_protocol_ports_bitmap(
            SOCK_DATA_HTTP1 as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_HTTP2 as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_DUBBO as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_SOFARPC as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_FASTCGI as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_BRPC as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_TARS as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_SOME_IP as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_MYSQL as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_POSTGRESQL as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_REDIS as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_KAFKA as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_MQTT as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_AMQP as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_OPENWIRE as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_NATS as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_PULSAR as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_ZMTP as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_DNS as c_int,
            CString::new("53,53053".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_MONGO as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_WEBSPHEREMQ as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_TLS as c_int,
            CString::new("443".as_bytes()).unwrap().as_c_str().as_ptr(),
        );
        set_protocol_ports_bitmap(
            SOCK_DATA_ISO8583 as c_int,
            CString::new("1-65535".as_bytes())
                .unwrap()
                .as_c_str()
                .as_ptr(),
        );
        //let hooked_socket_syscalls = [
        //    "read", "readv", "recvfrom", "recvmsg", "recvmmsg", "sendmsg", "sendmmsg", "sendto",
        //    "write", "writev",
        //];
        let hooked_socket_syscalls = [
            "readv", "recvfrom", "recvmsg", "recvmmsg", "sendmsg", "sendmmsg", "sendto", "writev",
        ];
        set_hooked_socket_syscalls(
            HookedSocketSyscallBitmap::from(hooked_socket_syscalls.as_slice()).0,
        );
        // dpdk enable
        // set_dpdk_trace_enabled(true);
        // disable_kprobe_feature();
        // set_virtual_file_collect(true);
        let udp_peer_id_enabled = env::var("UDP_TEST_PEER_ID")
            .map(|value| value != "0")
            .unwrap_or(true);
        set_udp_peer_id_enabled(udp_peer_id_enabled);
        info!("UDP peer socket ID isolation enabled={} for sample testing", udp_peer_id_enabled);
        if running_socket_tracer(
            socket_trace_callback, /* Callback interface rust -> C */
            1, /* Number of worker threads, indicating how many user-space threads participate in data processing */
            128, /* Number of page frames occupied by kernel-shared memory, must be a power of 2. Used for perf data transfer */
            65536, /* Size of the circular buffer queue, must be a power of 2. e.g: 2, 4, 8, 16, 32, 64, 128 */
            524288, /* Maximum number of hash table entries for socket tracing, depends on the actual number of concurrent requests in the scenario */
            524288, /* Maximum number of hash table entries for thread/coroutine tracing sessions */
            520000, /* Maximum threshold for cleaning socket map entries. If the current number of map entries exceeds this value, map cleaning operation is performed */
        ) != 0
        {
            println!("running_socket_tracer() error.");
            ::std::process::exit(1);
        }

        let feature: c_int = FEATURE_UPROBE_GOLANG;
        let pids: [c_int; 3] = [101, 202, 303];
        let num: c_int = pids.len() as c_int;
        let result = set_feature_pids(feature, pids.as_ptr(), num);
        println!("Result {}", result);

        // Test for dpdk
        //set_dpdk_cmd_name(
        //    CString::new("l2fwd".as_bytes()).unwrap().as_c_str().as_ptr
        //);
        //// i40e_recv_pkts, virtio_recv_pkts
        //// i40e_xmit_pkts, virtio_xmit_pkts, virtio_recv_mergeable_pkts
        //set_dpdk_hooks(
        //    DPDK_HOOK_TYPE_RECV as c_int,
        //    CString::new("rte_eth_rx_burst,virtio_recv_mergeable_pkts".
        //);
        //set_dpdk_hooks(
        //    DPDK_HOOK_TYPE_XMIT as c_int,
        //    CString::new("virtio_xmit_pkts".as_bytes()).unwrap().as_c_s
        //);
        //dpdk_trace_start();

        // test data limit max
        set_data_limit_max(10000);

        // Dump only inferred FastCGI traffic. Unix socket records are marked
        // with SOURCE 8 in the datadump output.
        let empty_string = CString::new("").expect("CString::new failed");
        if datadump_set_config(
            0,
            empty_string.as_ptr(),
            SOCK_DATA_DNS as c_int,
            empty_string.as_ptr(),
            0,
            1800,
            debug_callback,
        ) != 0
        {
            println!("datadump_set_config() error");
            ::std::process::exit(1);
        }

        print!("socket_tracer_start() finish\n");

        let stats = socket_tracer_stats();
        print!("{:#?}\n", stats);

        //// enable continuous profiler
        //if start_continuous_profiler(99, continuous_profiler_callback) != 0 {
        //    println!("start_continuous_profiler() error.");
        //    ::std::process::exit(1);
        //}

        //set_feature_regex(
        //    ebpf::FEATURE_PROFILE_ONCPU,
        //    CString::new(
        //        "^(java|nginx|profiler|telegraf|mysqld|.*deepflow.*|socket_tracer)$".as_bytes(),
        //    )
        //    .unwrap()
        //    .as_c_str()
        //    .as_ptr(),
        //);

        //// CPUID will not be included in the aggregation of stack trace data.
        //set_profiler_cpu_aggregation(0);

        bpf_tracer_finish();

        let stats = socket_tracer_stats();
        print!("{:#?}\n", stats);

        print!("start start ...\n");
        while socket_tracer_start() != 0 {
            print!("socket_tracer_start() error, sleep 1s retry.\n");
            std::thread::sleep(Duration::from_secs(1));
        }

        //thread::sleep(Duration::from_secs(60));
        //stop_continuous_profiler();
        //print!(
        //    "====== capture count {}, sum {}\n",
        //    get_counter(0),
        //    get_counter(1)
        //);
        //release_flame_graph_hash();
    }

    loop {
        thread::sleep(Duration::from_secs(5));
    }
}
```
