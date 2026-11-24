# 第二条批量 DNS 消息的 iovec 上限测试

2026-11-24 将 `EXTRA_LOOP_LIMIT` 从 1 调整为 **8**。在 Linux 4.14 和 4.19 上，
实际加载 common 字节码并完成开启、关闭 peer 隔离的分段 DNS 收发验证。
第一条消息的 `LOOP_LIMIT` 保持 18。

同日测试机切换到 Linux 5.10 后的大候选复测，见
[Linux 5.10 取值测试报告](udp-extra-iov-limit-linux-5.10-test-report-20261124.md)。
该报告区分独立输出程序与完整字节码加载；本报告的 4.14 / 4.19 结果继续保留。

## 环境与构建

| 项目 | 内容 |
| --- | --- |
| 分支 / 基线 HEAD | `codex/v6.6-udp-peer-isolation` / `bd34b31486d14d15dd053d512d05e00ea96398c7` |
| 构建机及运行机 | `10.50.5.27`，x86_64，`4.19.17-1.el7.x86_64` |
| 兼容性运行机 | `10.50.5.29`，x86_64，`4.14.15-1.el7.elrepo.x86_64` |
| 构建镜像 | `hub.deepflow.yunshan.net/public/rust-build:1.31` |
| eBPF 编译器 | Clang/LLVM 11.0.0，仓库 Makefile 的 `-O2` / BPF `-mcpu=v2` |
| 采集程序 | 在独立副本中追加载荷日志的 Rust `socket_tracer` sample |

构建目录从此前独立构建归档复制，未改动原构建工作区。候选测试开始前，
`socket_trace.bpf.c` 与基线 HEAD 的 SHA256 一致：

```text
04fcd664ab2c39ef68677182dc75208179c9828240d7764cb2daea0490281525
```

各候选仅修改 `EXTRA_LOOP_LIMIT`。选定 8 后重新生成七种 x86 socket 字节码
（common、3_10_0、5_2_plus、kfunc、kylin、rt、kprobe），再构建 C 库和 Rust sample。
本地最终源码与实际编译的内核源码仅有注释差异。

Rust 构建复用原归档的离线依赖解析，仍存在 `rustix 0.38.37 → 0.38.44`、
`libc 0.2.157 → 0.2.191`、`windows-link 0.2.0 → 0.2.1` 的锁文件差异，
详见 [原构建说明第 14.4 节](v6.6-udp-chat-recovery-20261119.md)。
本次未改动仓库依赖文件，结果不等同于严格使用原锁文件的完整 Agent 构建。

## Linux 4.14 候选值加载

使用实际 common ELF 的 `prog/tp/output_data`、`prog/kp/output_data` 两个完整程序节，
分别以 TRACEPOINT、KPROBE 类型调用 `BPF_PROG_LOAD`，不附加探针。
按项目旧内核加载逻辑替换 read helper 112/113 为 4、114/115 为 45，并完成 Map 重定位。
Map key/value 大小、类型和数组边界保持原值，独立加载器仅将 hash 容量缩小至最多 16 项。

| EXTRA_LOOP_LIMIT | 每个输出程序的静态指令数 | TP 加载 | KP 加载 |
| --- | ---: | --- | --- |
| 1 | 2483 | 通过 | 通过 |
| 2 | 2601 | 通过 | 通过 |
| 4 | 2833 | 通过 | 通过 |
| **8** | **3163** | **通过** | **通过** |
| 12 | 3535 | E2BIG | E2BIG |
| 16 | 3915 | E2BIG | E2BIG |
| 17 | 4010 | E2BIG | E2BIG |
| 18 | 4104 | E2BIG | E2BIG |

18 已超过旧内核 4096 条静态指令上限；12、16、17 虽未超过该值，仍被内核拒绝。
表中是关闭 verifier 日志后的实际加载结果，未记录完整拒绝日志，因此不据此给出精确的
verifier 状态数。选择 8 是在已通过的候选中留有余量的取值，**没有测试 9–11，不能称为最大值**。

## 实际采集验证

两台机器分别以隔离关闭、开启运行全新 sample 进程，均确认加载
`socket-trace-bpf-linux-common` 并进入 `TRACER_RUNNING`。
使用 [test_sendmmsg_iov.py](../test/udp-peer-id/test_sendmmsg_iov.py)，
在一个绑定 `127.0.0.2` 的 UDP socket 上向 `127.0.0.1:53053` 批量发送 DNS A + AAAA 查询。

| 场景 | 第二条消息的 iovec | 检查内容 |
| --- | --- | --- |
| single | 1 | 基本收发 |
| split_2 / split_4 / split_8 | 2 / 4 / 8 | 多段拼接后的完整载荷 |
| leading_empty_2 / leading_empty_4 / leading_empty_8 | 2 / 4 / 8，首项为空 | 跳过空项后仍采集完整载荷 |
| middle_empty_8 | 8，中间项为空 | 空项不阻断后续复制 |
| first_split_4 | 8，第一条消息另分为 4 段 | 主路径与附加路径同时分段 |
| over_limit | 9 | 接收端收到完整载荷，附加事件只包含前 8 项的前缀 |

每种模式运行 10 个场景、核对 20 条发送 callback；两台机器共核对 **80 条发送事件**。
接收端逐字节核对完整 DNS 报文；采集日志按 PID、FD、DNS transaction ID 关联，
逐字节核对载荷或预期前缀，同时检查 `cap_len`、完整 `syscall_len` 和无缺失/重复事件。

| 内核 | 隔离关闭 | 隔离开启 |
| --- | --- | --- |
| 4.14.15 | 20/20 通过 | 20/20 通过 |
| 4.19.17 | 20/20 通过 | 20/20 通过 |

两个模式均检查同一 peer 的稳定 `socket_id` 和每批两条消息的相邻序号。
开启隔离时另外检查全部 peer 序号为 0–19、无重复或缺失；关闭隔离时不要求跨批物理序号连续。

复现命令及 sample 的完整载荷日志格式见
[测试说明第 6 节](../test/udp-peer-id/README.md)。只运行通信脚本不代表 eBPF 采集验证通过。

## 证据与恢复

构建机归档：

```text
/home/jiping/deepflow/deepflow-1/udp-extra-iov-20261124.c4WCgj
```

Linux 4.14 归档：

```text
/tmp/udp-extra-iov-20261124.dpQZox
```

归档保留 `output-{limit}.elf`、`load-{limit}/results.json`（4.14）、
`runtime-results.json`、`expectations-{off,on}.json`、`tracer-{off,on}.log`，
以及独立加载器 `load_output.py`（4.14）、运行脚本 `run_runtime.py`。
构建机另有 `source/`、`build-{limit}.log`、`sample-c-build.log`、`sample-rust-build.log`。
实际 sample 的临时采集源码在 `source/agent/src/ebpf/samples/rust/socket-tracer/src/main.rs`，
增加 `UDP_IOV` 完整载荷记录，并通过 `UDP_TEST_PEER_ID=0|1` 控制隔离。

两台机器使用相同的 `socket_tracer-8`，SHA256：

```text
fb33aed0796d8668c766fd083ae4710d8b4fe9e94af974436e2b4374ff158bfc
```

原始结果、预期文件、采集日志和候选结果已取回本地：

```text
C:\Users\Yunshan\AppData\Local\Temp\udp-extra-iov-20261124\host-4.14
C:\Users\Yunshan\AppData\Local\Temp\udp-extra-iov-20261124\host-4.19
```

两台机器的测试进程均已退出。`runtime-results.json` 确认控制工具、sysctl、kprobe 定义
与测试前一致；额外通过 BPF ID 枚举确认没有遗留 program 或 Map。

本轮仅实际运行 common 变体，其他六种变体只验证编译。未覆盖其他内核、完整 Agent、
并发压力或每条消息目标不同的批次。KFUNC 输出路径问题仍按既定范围另行处理。
