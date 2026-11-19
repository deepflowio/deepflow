# UDP Peer Socket ID：Linux 5.10 全量复测报告

## 1. 结论与范围

2026-11-19 **22:48:07–22:49:16（Asia/Shanghai）**，在用户指定的 `192.168.10.12` 上，使用 Rust sample **`socket_tracer`** 重新执行 Linux 4.19 历史报告中的完整 UDP 测试集。

**结果：25 组正向场景、96 条预期事件、原有 8 项汇总检查全部通过；三种短地址发送的 EINVAL / 无 callback，以及部分成功 sendmmsg 的第二条无 callback 也通过自动检查。** 新增全量对照审计 8/8 通过，目标机两项源码契约测试通过，最终进程返回码为 0。

本报告记录的是一次新的 Linux 5.10 实测，不复用此前 22:17–22:18 那轮运行结果。Linux 4.19 历史结果和源码保留在 [原测试报告](udp-peer-socket-id-test-report-20261119.md)，回迁过程见 [恢复记录第 14 节](v6.6-udp-chat-recovery-20261119.md)。

结论限定于本机 Linux 5.10 的 **5.2+ eBPF 路径**及下列用例，不代表其他内核变体、完整 Agent、完整 CI 或压力测试通过。

## 2. 版本、构建与测试程序

| 项目 | 本轮实际值 |
| --- | --- |
| 测试主机 / 主机名 | `192.168.10.12` / `node` |
| 系统 | CentOS Linux 7.9.2009，x86_64 |
| 内核 | `5.10.201-1.el7.x86_64` |
| 仓库 HEAD | `378e616`，`v6.6` |
| tail-call 实现提交 | `b343d48`、`115a012`；`378e616` 仅补充契约测试和文档 |
| 采集程序 | Rust sample `socket_tracer`，不是完整 deepflow-agent |
| 加载变体 | `socket-trace-bpf-linux-5.2_plus` |
| 流量发生程序 | C 双 peer client/server、Python UDP syscall 用例 |
| 目标机 Python | 3.6.8 |
| 执行方式 | 直接在目标机运行，不在 Docker 中加载 eBPF |

### 2.1 二进制来源

复用恢复记录第 14.4 节中，按文档指定工具链完整执行 `make clean`、`make socket-tracer` 得到的测试程序：

```text
/home/jiping/deepflow/deepflow-1/udp-tailcall-validation-20261119.lLxdiv/socket_tracer
```

SHA256：

```text
49c89c2a49e4a2a53e9d4417f93d643b5e850981d22101dea32a855bd15482d9
```

原正式构建使用 `hub.deepflow.yunshan.net/public/rust-build:1.31`、devtoolset-11、LLVM 11、Rust/Cargo 1.83.0。复测前确认实现源码与构建副本一致，传输后在目标机再次确认二进制 SHA256。

**本轮没有重新编译，也没有重新链接 Rust 对象。** 原构建通过独立 `CARGO_HOME` 离线完成，其隔离锁文件调整仍适用：rustix `0.38.37 → 0.38.44`、libc `0.2.157 → 0.2.191`、windows-link `0.2.0 → 0.2.1`。原仓库依赖文件未修改，不能把本轮程序描述为严格使用原锁文件全部依赖版本的构建。

sample 保留测试采集调整：DNS datadump、打印 `UDP_PEER` callback 的长度和 txid、通过 `UDP_TEST_PEER_ID` 切换 peer 隔离。没有为本轮更改内核或用户态采集逻辑；也不能把它表述为未经采集调整的 HEAD sample。

### 2.2 与 Linux 4.19 测试集的一致性

以下三个脚本与 Linux 4.19 原归档逐字节一致，未删减用例或放宽校验：

| 脚本 | SHA256 |
| --- | --- |
| `run_host_validation.py` | `311c00a4ca79b3108df51d20fb9333a1c0e13d5c4eb466f4a265c94fa37a70a6` |
| `udp_syscall_cases.py` | `db49c373f088900f3b1942710d1256298e0af8ad3a85345b04966c0d7793414a` |
| `verify_runtime.py` | `7aa0031f603f089bf54e5ed2f56c19a52200efc34738f78465e596cc403d785e` |

双 peer C 程序使用同一组样例；仅通过 `run_target_validation.py` 指定新的归档 / 程序目录、包装退出清理，并调用新增的 `verify_full_regression.py`。

新增审计比较两轮预期的 case 集合、方向、txid、长度、syscall 来源、MSG_NUM、地址完整性、附加消息标记及 IP。PID、FD、临时端口、socket ID 不要求跨运行取相同数值；它们在本轮事件内部继续由原校验器关联和检查。

## 3. 本轮执行顺序

1. 确认目标机没有竞争的 socket_tracer / deepflow-agent，测试端口未占用；备份控制工具、kprobe_events、sysctl、BPF Map / program 清单。
2. 在目标机执行 UDP syscall 地址与 peer socket ID 两项源码契约测试，均通过。
3. 启用 peer 隔离，启动 socket_tracer，等待 5.2+ 加载成功并进入 TRACER_RUNNING。
4. 校验 Map 容量、C 双 peer 隔离，执行原 25 组正向 syscall 场景和三种短地址发送负向调用，再校验完整 callback / datadump。
5. 执行通配绑定回退，停止启用模式 tracer。
6. 关闭 peer 隔离，重新启动 tracer；检查 Map 缩容、物理 ID、总序号以及隔离校验器负向对照。
7. 比较 Linux 4.19 / 5.10 全量用例与事件，检查没有缺失或额外 callback，以及两个失败发送的无事件条件。
8. 停止全部测试进程，恢复控制工具，对照测试前后 Map / program、kprobe_events、sysctl；最终返回 0。

## 4. 25 组正向场景逐项对照

每条预期事件校验本轮 PID / FD、方向、txid、远端 IP / 端口、本地端口、callback 的 cap_len / syscall_len，以及对应 datadump 的 SOURCE_FN / MSG_NUM / SYSCALL_LEN。除既有双栈本地地址缺失分支外，同时校验本地 IP。

表中条数为该 case 的预期 UDP callback 数，不是 syscall 次数或完整 datadump 日志总行数。带 recvmmsg 的两消息场景仍只期望接收首条；没有把当前实现描述为任意 batch 全量输出。

| case | 场景及检查点 | 4.19 已验证条数 | 5.10 本轮通过条数 |
| --- | --- | ---: | ---: |
| `u4_to` | IPv4 sendto / recvfrom，请求和回复地址、长度 | 4 | 4 |
| `u6_to` | 原生 IPv6 sendto / recvfrom | 4 | 4 |
| `u4_msg` | IPv4 sendmsg / recvmsg，未 connect 远端 | 4 | 4 |
| `u6_msg` | 原生 IPv6 sendmsg / recvmsg | 4 | 4 |
| `u4_mmsg` | IPv4 sendmmsg / recvmmsg，成功消息数及第二条发送长度 | 5 | 5 |
| `u6_mmsg` | 原生 IPv6 sendmmsg / recvmmsg | 5 | 5 |
| `dual_msg` | 双栈接收 IPv4-mapped 地址并归一化 | 2 | 2 |
| `dual_mmsg` | 双栈 mmsg 地址、附加发送、消息数 | 3 | 3 |
| `v6_24_to` | IPv6 sockaddr 长度 / 接收入口容量 24，sendto / recvfrom | 4 | 4 |
| `v6_24_msg` | IPv6 sockaddr 长度 / 接收入口容量 24，sendmsg / recvmsg | 4 | 4 |
| `v6_24_mmsg` | IPv6 sockaddr 长度 / 接收入口容量 24，sendmmsg / recvmmsg | 5 | 5 |
| `v6_short_to` | IPv6 接收入口容量 16、返回 28，不误读完整地址 | 2 | 2 |
| `v6_short_msg` | IPv6 recvmsg 容量 16，不误读完整地址 | 2 | 2 |
| `v6_short_mmsg` | IPv6 recvmmsg 容量 16，不误读完整地址 | 3 | 3 |
| `v4_short` | IPv4 接收入口容量 8，不使用旧远端 | 2 | 2 |
| `v4_noname` | 不提供 msg_name，不使用旧远端 | 2 | 2 |
| `v4_partial` | sendmmsg 仅第一条合法，成功数 / MSG_NUM 为 1 | 4 | 4 |
| `v4_connzero` | 已 connect IPv4，目标长度 / 接收入口容量为 0 | 4 | 4 |
| `v6_connzero` | 已 connect IPv6，目标长度 / 接收入口容量为 0 | 4 | 4 |
| `u4_stale` | 同 FD 先完整接收，再以 8 / 0 容量接收另一 peer | 6 | 6 |
| `dual4_sendto` | AF_INET6 socket 使用 AF_INET 目标 sockaddr，sendto | 2 | 2 |
| `dual4_sendmsg` | AF_INET6 socket 使用 AF_INET 目标 sockaddr，sendmsg | 2 | 2 |
| `dual4_sendmmsg` | AF_INET6 socket 使用 AF_INET 目标 sockaddr，sendmmsg | 3 | 3 |
| `u4_peerports` | IPv4 同 IP 不同源端口，回复顺序 B、A | 8 | 8 |
| `u6_peerports` | IPv6 同 IP 不同源端口，回复顺序 B、A | 8 | 8 |
| **合计** | **25 组，原校验器逐事件通过** | **96** | **96** |

两轮完整语义投影一致；本轮实际 callback 与本轮预期一一对应，**缺失 0、额外 0**。

## 5. 负向与隔离功能检查

### 5.1 短目标地址与部分成功发送

| 负向条件 | 通信结果 | 采集结果 |
| --- | --- | --- |
| sendto 传入 8 字节目标 sockaddr | EINVAL，原发生器断言通过 | txid=2041 的 callback 为 0 |
| sendmsg 传入 8 字节目标 sockaddr | EINVAL，原发生器断言通过 | 同一 txid=2041 的 callback 为 0 |
| sendmmsg 传入 8 字节目标 sockaddr | EINVAL，原发生器断言通过 | 同一 txid=2041 的 callback 为 0 |
| sendmmsg 两条中仅第一条合法 | 返回成功数 1；datadump MSG_NUM=1 | 第二条 txid=2032 的 callback 为 0 |

三个短地址失败调用复用同一报文，因此不能将 txid=2041 表述为三个不同 transaction。上述无事件条件是对原 96 条正向预期之外的额外检查，不计入 96 条之内。

```text
[COMM OK] invalid sockaddr rejected for sendto/sendmsg/sendmmsg
[NEGATIVE] short destination txid=2041 callbacks=0; partial second txid=2032 callbacks=0
```

### 5.2 原有 8 项汇总检查

| 原检查 | 本轮结果 |
| --- | --- |
| 启用时 LRU Map 容量 | LRU_HASH，key=48、value=16、max_entries=40960 |
| IPv4 双 peer 同 FD，A、B 请求 / B、A 回复 | 两个独立 ID，各自双向一致，cap_seq=0、1 |
| UDP syscall 通信 | 全部通过，包括短目标地址的 EINVAL 断言 |
| UDP tuple / metadata / mmsg / peer-port | 25 组、96 条全部通过 |
| 通配本地地址缺失回退 | 一个物理 ID，cap_seq=0、1、2、3 |
| 关闭时 LRU Map 容量 | max_entries=1 |
| 关闭功能后的物理 ID | 两个 peer 共用一个物理 ID，总序号 0、1、2、3 |
| 关闭功能的隔离校验器负向对照 | 按预期拒绝日志，非零返回计为该负向测试通过 |

开启时 peer Map ID 为 86，关闭后重新创建的 peer Map ID 为 117；两轮退出后都已释放。Map ID 仅是本次运行标识，不作为跨运行期望值。

## 6. 本轮真实日志证据

本节摘录来自本次独立目标机归档。Rust 日志使用 UTC（Z）；测试起止时间和 datadump 使用 Asia/Shanghai。

### 6.1 两轮加载成功

```text
[2026-11-19T14:48:31.941Z INFO  socket_tracer::ebpf] [eBPF] INFO bpf load "socket-trace-bpf-linux-5.2_plus" succeed.
[2026-11-19T14:48:34.071Z INFO  socket_tracer::ebpf] [eBPF] INFO [eBPF Kernel Adapt] Linux 5.10.201-1.el7.x86_64 adapt success. Set the status to TRACER_RUNNING
[2026-11-19T14:49:09.370Z INFO  socket_tracer::ebpf] [eBPF] INFO bpf load "socket-trace-bpf-linux-5.2_plus" succeed.
[2026-11-19T14:49:11.462Z INFO  socket_tracer::ebpf] [eBPF] INFO [eBPF Kernel Adapt] Linux 5.10.201-1.el7.x86_64 adapt success. Set the status to TRACER_RUNNING
```

### 6.2 sendmmsg 第二条独立长度与序号

```text
UDP_PEER queue=0 process=python3 pid=2834 fd=4 direction=out socket_id=90008591157418917 cap_seq=0 local=127.0.0.2:49962 remote=127.0.0.1:53053 cap_len=24 syscall_len=24 txid=2009
UDP_PEER queue=0 process=python3 pid=2834 fd=4 direction=out socket_id=90008591157418917 cap_seq=1 local=127.0.0.2:49962 remote=127.0.0.1:53053 cap_len=37 syscall_len=37 txid=2010
```

两条发送共用同一 peer ID，长度分别为 24、37，cap_seq 为 0、1。接收端 recvmmsg 仍只输出首条，符合原测试范围。

### 6.3 短接收地址不复用历史 peer

```text
UDP_PEER queue=0 process=python3 pid=2834 fd=3 direction=in socket_id=162066185195346881 cap_seq=0 local=127.0.0.1:53053 remote=127.0.0.2:36848 cap_len=24 syscall_len=24 txid=2038
UDP_PEER queue=0 process=python3 pid=2834 fd=3 direction=in socket_id=162066185195346880 cap_seq=1 local=127.0.0.1:53053 remote=0.0.0.0:0 cap_len=24 syscall_len=24 txid=2039
UDP_PEER queue=0 process=python3 pid=2834 fd=3 direction=in socket_id=162066185195346880 cap_seq=2 local=127.0.0.1:53053 remote=0.0.0.0:0 cap_len=24 syscall_len=24 txid=2040
```

入口容量分别为 16、8、0。后两次未复用第一次的远端，而是保留不完整地址并回退物理 ID；不能将该回退序号误解为新的独立 peer 序号。

### 6.4 双 peer 及同 IP 不同端口

```text
[OK] UDP peer socket ID isolation
  peer=127.0.0.2 fd=3 socket_id=666469343460842389 cap_seq=0,1
  peer=127.0.0.3 fd=3 socket_id=666469343460842390 cap_seq=0,1
[PEER OK] u4_peerports endpoint=34251 socket_id=162066185195346902 seq=[0, 1]
[PEER OK] u4_peerports endpoint=50397 socket_id=162066185195346901 seq=[0, 1]
[PEER OK] u6_peerports endpoint=35623 socket_id=162066185195346908 seq=[0, 1]
[PEER OK] u6_peerports endpoint=45720 socket_id=162066185195346909 seq=[0, 1]
```

### 6.5 原校验器与新增审计

```text
[OK] 96 events verified: tuples, callback lengths, SOURCE_FN, MSG_NUM, sendmmsg and peer-port sequences
[PASS] exact_96_callbacks_no_missing_or_extra
[PASS] five_two_plus_loaded_and_running_disabled
[PASS] five_two_plus_loaded_and_running_enabled
[PASS] original_tuple_metadata_verifier_passed
[PASS] partial_sendmmsg_failed_second_message_no_callback
[PASS] same_25_cases_and_96_expectations_as_4_19
[PASS] same_eight_summary_checks_as_4_19
[PASS] short_destination_three_syscalls_einval_no_callback
```

## 7. 归档与复核

本地独立归档根目录：

```text
/home/jiping/deepflow/deepflow-1/udp-5.10-full-regression-20261119.xmSvDZ
```

目标机目录：

```text
/root/udp-full-regression-20261119-xmSvDZ
```

本地根目录保存二进制、原始三个脚本、目标机包装器、新增全量审计器、构建溯源和测试前工作区快照。`baseline-4.19/` 保存历史预期与汇总；`target-192.168.10.12/` 保存从本轮目标机取回的日志和结果。

| 目标机证据文件 | 内容 |
| --- | --- |
| `runtime.started` / `runtime.finished` / `runtime.exit-code` | 起止时间及返回码 0 |
| `contract-tests-target.log` | 目标机两项源码契约测试 |
| `tracer-enabled.log` / `tracer-disabled.log` | 两轮完整加载及 callback / datadump 日志 |
| `runtime-communication.log` | 全部 syscall 通信及 EINVAL 断言 |
| `runtime-expectations.json` / `syscall-runtime.log` | 96 条预期和对应采集日志 |
| `runtime-verification.log` | 原校验器逐 case 结果与 96 条汇总 |
| `runtime-results.json` | 原有 8 项汇总检查 |
| `full-regression-results.json` | 25 组逐项历史对照、8 项新增审计、负向 txid / 事件数、加载证据 |
| `peer-enabled-verification.log` / `peer-disabled-negative-verification.log` | 开关正向与负向对照 |
| `maps-enabled.json` / `maps-disabled.json` | 开关两轮真实 Map 类型、尺寸和容量 |
| `cleanup-results.json` | 现场恢复结果 |

以下命令只复核已取回的日志，**不会加载 eBPF 或更改目标机状态**：

```bash
ARTIFACTS=/home/jiping/deepflow/deepflow-1/udp-5.10-full-regression-20261119.xmSvDZ
RESULTS="$ARTIFACTS/target-192.168.10.12"
python3 "$ARTIFACTS/verify_runtime.py" \
  "$RESULTS/runtime-expectations.json" "$RESULTS/syscall-runtime.log"
python3 "$ARTIFACTS/peer/verify_socket_tracer.py" "$RESULTS/peer-enabled.log"
python3 "$ARTIFACTS/verify_full_regression.py" "$RESULTS"
```

若再次实测，必须复制到新的独立归档，重新备份控制工具及内核状态，再运行 `run_target_validation.py`；不能覆盖本轮结果或直接沿用旧的恢复基线。

## 8. 现场恢复与尚未覆盖范围

```json
{
  "control_binary_restored": true,
  "kprobe_events_unchanged": true,
  "sysctls_unchanged": true,
  "maps_new_ids": [],
  "programs_new_ids": []
}
```

本轮启动的 socket_tracer、UDP client/server 均已退出，`/usr/bin/deepflow-ebpfctl` 已恢复且 SHA256 一致，未更改 kptr_restrict / perf_event_paranoid，无新增 BPF Map / program 残留。原工作区的三个既有 tracked 修改保持不变。

未覆盖范围保持明确：

- 只实际加载 5.2+ 变体；KFUNC、KPROBE_ONLY、其他内核不因本轮通过而自动获得运行验证。
- 未进行完整 Agent、完整 CI、并发压力、LRU 耗尽、任意 batch 全量输出或同 batch 不同目标 peer 测试。
- 当前 recvmmsg 只输出首条，sendmmsg DNS 附加路径输出第二条。
- 双栈 / 通配绑定缺少本地 IP 时仍可能回退物理 socket ID，这是原测试明确检查的行为。
- 原 Linux 4.19 两消息用例的 DNS qtype 为 A + A；本轮保持同一测试集，真实 A + AAAA 专项仍未覆盖。
- 原 Linux 4.19 历史报告未被改写为新实现的 4.19 运行结果。本轮仅对其完整测试集在 5.10 上重新执行。

本轮未修改采集实现，新增测试文档尚未另行提交或推送。
