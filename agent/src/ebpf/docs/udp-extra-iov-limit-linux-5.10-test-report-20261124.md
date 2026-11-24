# Linux 5.10 的 EXTRA_LOOP_LIMIT 取值测试

2026-11-24，`10.50.5.29` 从 4.14 切换为 `5.10.201-1.el7.x86_64` 后重新测试。
综合 Linux 4.14、4.19（common）及 5.10（5.2+）的实测结果，**统一取值为 8**。
**5.10 专用取值建议为 12；16 是当前代码和工具链下实测通过的最大有效值，17、18 失败。**
16 的 verifier 复杂度余量仅约 0.7%，12 留有约 5.7%。
当前源码全局值继续保持 8，以保留已验证的 Linux 4.14 兼容性。

## 环境与方法

| 项目 | 内容 |
| --- | --- |
| 分支 / 基线 | `codex/v6.6-udp-peer-isolation` / `bd34b31486d14d15dd053d512d05e00ea96398c7` |
| 测试机 | `10.50.5.29`，x86_64，`5.10.201-1.el7.x86_64` |
| 构建机 | `10.50.5.27`，`4.19.17-1.el7.x86_64` |
| 构建镜像 | `hub.deepflow.yunshan.net/public/rust-build:1.31` |
| eBPF 工具链 | Clang/LLVM 11.0.0，仓库 Makefile，`-O2` / `-mcpu=v2` |
| 实际加载的采集变体 | `socket-trace-bpf-linux-5.2_plus` |

从上轮独立构建目录复制新的隔离副本，逐个修改 `EXTRA_LOOP_LIMIT`，重新编译
5.2+ ELF。common 候选复用上轮相同工具链构建的 ELF。
原构建目录、原 4.14 测试归档和仓库生产源码均保持原样。

独立加载器完成原始 ELF 的 Map 重定位，以原程序类型调用 `BPF_PROG_LOAD`，不附加探针。
Map 类型、key/value 大小和数组边界保持原值，仅将 hash 容量缩小至最多 16 项。
在 5.10 上保留原生 read helper，不执行 4.14 所需的旧 helper 替换。

## 独立输出程序与完整加载的区别

对 1、2、4、8、12、16、17、18 八个候选，common 和 5.2+ 的
`prog/tp/output_data`、`prog/kp/output_data` 均加载成功，共 32 次成功加载。
但 5.2+ 的 syscall 程序还包含随上限增大的内联路径，独立输出程序成功不足以证明整个变体可用。

18 的完整 sample 加载失败于 `df_T_exit_recvmmsg`，随后自动回退到 common。
运行脚本要求日志中明确出现 5.2+ 的加载成功记录，因此识别并终止该轮，未将回退算作通过。
随后补测 syscall 程序和完整 ELF，得到以下边界：

| 候选值 | exit_recvmmsg 静态指令数 | verifier 处理指令数 | 该程序加载 | 完整变体 / 真实收发 |
| --- | ---: | ---: | --- | --- |
| 8 | 20320 | 910170 | 通过 | 完整 sample 两种隔离模式通过 |
| **12** | **20696** | **943010** | **通过** | **81/81 程序节加载、两种隔离模式收发通过** |
| 16 | 21074 | 992556 | 通过 | 81/81 程序节加载、两种隔离模式收发通过 |
| 17 | 21168 | 1000001 | E2BIG | 必需 syscall 程序被拒绝 |
| 18 | 21265 | 1000001 | E2BIG | 完整 sample 加载失败并回退，按失败处理 |

1、2、4 的 `exit_recvmmsg` 也加载成功，静态指令数分别为 19658、19751、19943。
12、16 的完整加载测试覆盖 ELF 中全部 81 个非空可执行程序节，按 tracepoint 或 kprobe
类型加载，包含 syscall、uprobe、kprobe 及 tail-call 目标；不只检查单个输出函数。

使用 `BPF_LOG_STATS` 取得的内核原始拒绝信息：

```text
BPF program is too large. Processed 1000001 insn
processed 1000001 insns (limit 1000000)
```

因此 17、18 触发的是 **100 万条 verifier 处理指令的复杂度限制**。
用户态加载器对 E2BIG 仍打印“超过 4096 条指令”，该通用提示不能作为这次 5.10 的失败原因。

复制函数同时受 `LOOP_LIMIT=18` 限制，继续增大 `EXTRA_LOOP_LIMIT` 不会扩展到 18 项以上。
本次 16 的边界只适用于当前源码、编译器和目标内核；后续代码变化仍需重新验证。

## 真实 DNS 采集验证

使用 [test_sendmmsg_iov.py](../test/udp-peer-id/test_sendmmsg_iov.py)，
同一 socket 绑定 `127.0.0.2`，向 `127.0.0.1:53053` 批量发送真实 DNS A + AAAA 请求。
每种模式启动新的 sample，严格确认 5.2+ 加载成功并进入 `TRACER_RUNNING`。

| EXTRA_LOOP_LIMIT | 每轮场景数 | 关闭隔离 | 开启隔离 |
| --- | ---: | --- | --- |
| 8 | 10 | 20/20 发送事件通过 | 20/20 发送事件通过 |
| 12 | 14 | 28/28 发送事件通过 | 28/28 发送事件通过 |
| 16 | 16 | 32/32 发送事件通过 | 32/32 发送事件通过 |

合计核对 **160 条发送 callback**。覆盖单段、2/4/8/12/16 段（不超过本轮候选值）、
首个 iovec 为空、中间项为空、第一条消息分为 4 段，以及第二条消息超过上限一项时的截断。
空项同样占一个 iovec 名额。

接收端逐字节核对完整报文；采集日志按 PID、FD、transaction ID 关联，
逐字节核对完整载荷或预期前缀，同时检查 `cap_len`、完整 `syscall_len` 和事件无缺失/重复。
两种模式均检查同一 peer 的稳定 ID、每批两个事件的相邻序号。
开启隔离时另外检查全部 peer 序号从 0 开始、连续且无重复；关闭时不要求跨批物理序号连续。

## 测试二进制与复现

8 复用上轮七种字节码均为 8 的 sample。12、16、18 分别将本轮对应的 5.2+ ELF 转换为
C 数组，重建 `libtrace.a`，清理并重新构建 Rust sample 包；其他六种字节码仍复用 8。
已逐字节确认新 ELF 包含于对应 sample，运行时另外核对实际加载的变体。
Rust 离线依赖解析沿用 [上轮构建说明](udp-extra-iov-limit-test-report-20261124.md)，
不等同于严格使用仓库原锁文件的完整 Agent 构建。

| sample | SHA256 |
| --- | --- |
| 8 | `fb33aed0796d8668c766fd083ae4710d8b4fe9e94af974436e2b4374ff158bfc` |
| 12 | `7886b6dcc276547c8a3b186498cd75606dd47ce7d748463c2fcc0b19f046bf19` |
| 16 | `93aeb59ceb097bafbd308fa07f6b69a592cb9ff3a02a94fc81562252423500ed` |
| 18（失败对照） | `07185f148357f97b3270c5d9e8ccbd4cee4e04365ce5ffa11549d6a6027c0303` |

采集程序在独立测试副本中输出 `UDP_IOV` 载荷记录，并通过 `UDP_TEST_PEER_ID=0|1`
控制隔离。流量生成和日志核对示例（先启动对应 sample，核对加载结果，再生成流量）：

```bash
python3 test_sendmmsg_iov.py expectations.json --limit 12
# 停止 sample、等待日志落盘后；开启隔离时追加 --peer-id-enabled
python3 test_sendmmsg_iov.py expectations.json --tracer-log tracer.log --peer-id-enabled
```

完整日志格式见 [测试 README 第 6 节](../test/udp-peer-id/README.md)。

## 归档与恢复

构建机归档：

```text
/home/jiping/deepflow/deepflow-1/udp-extra-iov-5.10-20261124.5UV97A
```

目标机归档：

```text
/tmp/udp-extra-iov-5.10-20261124.bw7dCD
```

归档包括各候选 ELF、`load-matrix.json`、`load-recvmmsg-*`、`stats-recvmmsg-*`、
`load-all-{12,16}`、独立加载器、`limit-{8,12,16,18}/` 中的运行脚本、日志、预期及结果。
构建机另有构建日志、sample、字节码嵌入核对结果和独立源码。
原始 JSON / 日志 / 脚本已取回本地目录：

```text
C:\Users\Yunshan\AppData\Local\Temp\udp-extra-iov-20261124\host-5.10
```

各轮 `runtime-results.json` 确认控制工具、sysctl、kprobe 定义已恢复。
最终 `cleanup-audit.json` 通过 BPF ID 枚举确认 program、Map 均为空，kprobe 定义无遗留。
本轮不覆盖 KFUNC、其他内核、完整 Agent 集成或并发压力。
