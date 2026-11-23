# v6.6 UDP Peer ID 最小移植

## 范围与开关

移植来源：`7fbe86e01ee88c43138df7324c57240f06badfa4`
（`fix(agent): isolate UDP peer metadata for socket tracing`）。
基于 v6.6 及 `5a32767e225d2e7ad17c538d104aa2d8e467afa2`
的 UDP 历史远端地址缓存移除修复实现，不恢复历史地址查询。

```yaml
inputs:
  ebpf:
    socket:
      tunning:
        udp_peer_id_enabled: false
```

默认关闭；修改后需要重启 Agent。独立 `socket_tracer` 样例可通过
`DF_UDP_PEER_ID_ENABLED=1 ./socket_tracer` 开启，未设置或设置为 `0` 时关闭。

开启后，只在数据输出前改写 UDP 事件的 `socket_id` 和 `data_seq`
（用户态 `cap_seq`）。PeerKey 包括物理 socket ID、本地与远端地址、两端端口及
地址长度；IPv4 地址的高 12 字节及 key padding 清零。
同一物理 socket 的不同 peer 使用独立 ID、独立序号；同一 peer 双向共享 ID、序号。

## 保持不变的逻辑

- `socket_info_map` 中的物理 ID、协议推断、`trace_process`、重组状态不改写。
- TCP、关闭事件、配置关闭、端点不完整或 Map 操作失败时保留原有输出元数据。
- 不新增 UDP 地址采集或 wildcard 本地地址补偿；无法得到完整端点时不做 peer 隔离。
- 不改变原有 tail-call 路由，不引入 tracing 程序到 tracepoint 程序的 tail call。
- 附加 DNS 消息仍走原有复制函数，iovec 遍历上限仍为 18，不缩减到 1。
- Peer ID 复用原有 ID 分配器；不改变物理 socket 的生命周期或清理逻辑。

## 与完整上游实现的取舍

Peer 状态容量为 40960，当前各变体统一使用 LRU Hash；LRU 淘汰后同一 peer
再出现会获得新 ID，序号重新开始。关闭配置时，用户态加载前将 peer 状态 Map
缩到 1 项，但不会跳过 Map 创建，因此仍要求目标内核支持 LRU Hash。

2026-11-20 的初版根据 `LINUX_VER_3_10_0` 将 3.10 变体降级为普通 Hash，
未区分厂商内核的回移能力；当前工作区已移除该分支，不再仅凭 3.10 版本号
判定不支持 LRU Hash。初版普通 Hash 的验证不能替代统一 LRU 实现的验证。

用户补充的实机结果：`192.168.10.12`，主机名 `node`，内核
`3.10.0-1160.102.1.el7.x86_64`，`CONFIG_BPF_SYSCALL=y`；直接调用
`bpf(BPF_MAP_CREATE)` 创建普通 Hash 和 LRU Hash 均成功。LRU 容量设为 2
时连续插入 3 个 key 全部成功，旧 key 被淘汰、新 key 可查询，验证了该 EL7
内核的 LRU 支持，不能按上游 3.10 的能力推断其不支持。测试 Map 未固定，FD
已关闭。此处记录的是用户提供的 Map 能力验证，不等于本轮完整 tracer 实测。

该结果仅覆盖上述具体内核，不推广到其他 3.10 厂商内核或更早 EL7 版本；本次
移除版本条件不引入运行时自动降级。完整 tracer 的本轮功能实测仍以 5.10 为准。
已核对 clean 构建的 3.10 ELF：`__udp_peer_map` 的类型为 9（LRU Hash），
key 为 48 字节、value 为 16 字节、默认容量为 40960。Python 2/3 各 5 项
契约测试通过，并断言该 Map 不再包含 3.10 条件或普通 Hash 降级分支。

PeerKey 和待插入状态放在独立、单元素的 per-CPU scratch Map，避免直接输出路径
增加栈变量后使 Go TLS 等程序超过 BPF 的 512 字节栈限制。该 scratch 不保存业务历史，
不占用或覆盖既有 socket/trace 状态。

主消息复制成功后，一次预留本次输出需要的序号：普通消息预留 1 个；带第二条
DNS 消息的 mmsg 预留 2 个。附加消息继续复制主消息头并将序号加 1，因此不需要
跨复制 helper 持有 peer Map Value 指针，也不需要修改原有附加消息复制路径。

与上游“附加消息复制成功后再分配序号”不同，如果第二条消息复制失败，预留序号
会留下空洞，但后续消息不会复用它。例如主消息输出 0、附加消息失败后，下一条为 2。
此处选择保留 v6.6 原有复制逻辑和 verifier 控制流，而非为消除空洞扩展输出路径。

## 2026-11-20 初版验证

验证日期：2026-11-20。构建使用恢复记录指定的
`hub.deepflow.yunshan.net/public/rust-build:1.31` 镜像，
GCC 11.2.1、LLVM 11、Rust/Cargo 1.83.0，在独立源码副本执行
`make clean && make socket-tracer`，不清理原工作区。

```bash
make -C agent/src/ebpf/test test_udp_peer_cache_contracts test_udp_peer_socket_id_contracts
make -C agent/src/ebpf/test test_udp_peer_cache_contracts test_udp_peer_socket_id_contracts PYTHON=python2
```

新增测试提取真实 C helper，用 stub Map 编译执行，覆盖配置关闭、无开关/无 scratch、
非 UDP、零物理 ID、缺失端点、双 peer、独立物理 socket、IPv4 高字节归一化、IPv6、
mmsg 序号预留与复制失败空洞、Map 插入失败、淘汰后新 ID，以及输出路径和 iovec
上限不变。原 UDP 历史地址缓存移除回归测试继续保留。

### 构建与自动检查结果

| 检查 | 结果 |
| --- | --- |
| 独立副本 `make clean && make socket-tracer` | 通过 |
| common、3.10、5.2+、KFUNC、Kylin、RT、KPROBE ELF 编译 | 全部通过；不代表全部实机加载通过 |
| Python 3 / Python 2 契约测试 | 各 5 项通过 |
| 5 个修改 Rust 文件的 rustfmt 检查 | 通过 |
| 真实 `EbpfSocketTunning` 及 serde helper 的隔离测试 | 默认关闭、YAML 开启、模板解析、非法值拒绝通过 |
| 完整 Agent 配置单测 | 未完成：离线环境缺少 `hpack-rs` Git 依赖，不计为通过 |

离线构建仅在独立副本将样例依赖 `rustix 0.38.37` 更新为已缓存的 `0.38.44`
及其锁文件联动项；实际工作区依赖文件未修改，差异保存在归档的
`Cargo.lock.offline.patch`。

### Linux 5.10 实机结果

目标：`192.168.10.12`，内核 `5.10.201-1.el7.x86_64`。使用上述 clean 构建的
`socket_tracer`，检查每种 ELF 均实际嵌入该二进制。未进行 KPROBE_ONLY 实测。
测试仅为本次 tracer 的 DNS 端口 bitmap 增加 53053/53054/53055/53057，
避免样例默认只识别 53 端口影响测试；未修改样例原有 DNS 配置或其他进程的 Map。

| 用例 | 开启 | 关闭 |
| --- | --- | --- |
| IPv4 双 peer：A/B 请求、B/A 反序响应 | 独立 ID，各自双向序号 0、1 | 保持共享物理 ID |
| IPv6 同 IP、不同端口双 peer | 独立 ID，各自双向序号 0、1 | 保持共享物理 ID |
| wildcard 本地 IP 不完整 | 回退共享物理 ID | 保持物理 ID |
| sendmmsg 两条 DNS 后继续 sendmsg | 同 peer ID，序号 0、1、2 | 保持原有输出行为 |
| TCP HTTP 请求/响应 | 同一服务端物理 ID，不受 peer 改写影响 | 原有行为 |
| Peer Map 容量 | 40960 | 1 |
| 读取 `socket_info_map` 物理 ID 与输出对比 | 物理 ID 未被输出 peer ID 覆盖 | 输出 ID 等于物理 ID |

mmsg 实测使用 connected socket、同一 peer、两条等长消息且全部发送成功；
不同 peer、不等长消息、部分成功等工况未在本轮实测，不扩展为这些工况的修复结论。

**实际加载的是 common ELF，而非 5.2+。** 5.2+ ELF 在 `df_T_exit_write`
加载时返回 `E2BIG (errno 7)`，原有加载器回退 common。为确认是否属于本次回归，
另将同一加载器的 5.2+ ELF 替换为从基线 `5a32767` 原始源码编译的 ELF，结果
同样在 `df_T_exit_write` 返回 E2BIG、回退 common。因此本次保留基线加载策略，
不额外引入 output tail-call 拆分。不能把 common 的用例通过记录为 5.2+ 加载通过。

测试结束确认没有新增 BPF Map、Program 或 kprobe 残留，sysctl 恢复原值；
`/usr/bin/deepflow-ebpfctl`、原日志和控制 socket 均恢复。
Linux 4.14、4.19、3.10 及 KFUNC/fentry 的实际加载未在本轮验证，不计为通过。

### 构建追溯

- 构建时源码：`5a32767e225d2e7ad17c538d104aa2d8e467afa2` 加本次移植修改（构建时尚未提交）；不是历史 `115a012` 二进制。
- 二进制 SHA256：`c120167d0be971f894a5ad4f2133b7c25a5d73a532c5ca3a3e28c2f32edf946a`。
- 本机归档：`/home/jiping/deepflow/deepflow-1/udp-peer-minimal-validation-20261120.YL2ltV`。
- 归档包含完整构建日志、源码副本、七种 ELF 嵌入校验、回归日志、`runtime-results.json` 和基线加载对照日志。

## 2026-11-23：修复 CI 指令数超限

`4f91668` 的 common ELF 中，`df_TP_output_data` 和 `df_KP_output_data`
均有 4135 条指令，超过 `test_insns_cnt` 的 4096 条门槛。此前执行的
`make clean && make socket-tracer` 只验证构建，不执行 `make test`；
Python 契约测试及 Linux 5.10 实机通过也不能替代这个兼容性检查。

本轮不放宽检查门槛、不增加 tail call、不缩减 18-iovec 上限，也不增加 BPF
栈上的 PeerKey。改为复用真实 `__tuple_t`，将连续的物理 socket ID 与 tuple
一次复制到对齐的 per-CPU scratch，再从 scratch 校验 ID、地址长度、端口及地址，
减少 packed 输出结构的逐字段读取和重复复制。编译期断言确保源结构中 socket ID
与 tuple 的偏移符合连续复制要求；复制失败直接保留物理元数据。

PeerKey 仍按完整端点隔离，额外携带的 L4 协议字段恒为 UDP；key 保留字段及
IPv4 双端地址高 12 字节显式清零，避免 scratch 历史字节影响 key。
测试改为读取生产 `__tuple_t` 定义，并补充读取失败、scratch 非零初值、
本地与远端 IPv4 高字节同时非零的回归覆盖。

完整 eBPF 构建、自测应包含最后一条命令，不能仅构建样例：

```bash
make clean
make socket-tracer
make test
```

### 本轮构建与指令数结果

使用与初版相同的构建镜像和工具链，在独立源码副本中重新执行上述三个命令，
全部通过；`make test` 实际执行了原有 `test_insns_cnt`，没有跳过或放宽检查。

| 检查 | 结果 |
| --- | --- |
| `df_TP_output_data` / `df_KP_output_data` | 均从 4135 降至 4080 条，减少 55 条 |
| common ELF 所有 81 个函数 | 全部不超过 4096；最大为 `df_TP_io_event`，4083 条 |
| 3.10、Kylin、RT、KPROBE ELF 静态指令数 | 各变体最大均为 4083；仅编译及静态检查，不代表对应内核实测 |
| common、3.10、5.2+、KFUNC、Kylin、RT、KPROBE 编译及二进制嵌入 | 七种均通过 |
| `make test` | 原生测试及两组 Python 契约测试全部通过 |
| Python 3 / Python 2 契约测试 | 各 5 项通过 |
| ARM64 定义的 common BPF 编译及静态检查 | 通过；两个 output 均为 4080，最大为 4083；未做 ARM64 实机验证 |
| `git diff --check` | 通过 |

`test_insns_cnt` 检查的是 common ELF。5.2+ 和 KFUNC 变体仍包含超过 4096
条指令的程序（修正十六进制符号大小的统计后，5.2+ 最大为 25231，KFUNC
最大为 25230；此前的 8526 漏计了十六进制大小的函数），不能把 common 的检查通过扩展为所有
变体均满足 4096 限制，也不能据此声明 5.2+ 或 KFUNC 实机加载成功。

本轮样例构建保留原锁定的 `rustix 0.38.37`，样例 `Cargo.lock` 与工作区完全
一致，不再采用初版离线验证的依赖版本替换。原生测试需要的 `libtrace_utils.a`
从真实源码在临时独立 Cargo workspace 中重新构建，再交给原 `make test`
使用；未修改仓库中的 Cargo 配置或锁文件。完整 Agent workspace 的测试及全部
CI 流程未在本轮执行，不计为通过。

### 重新切换至 Linux 5.10 后的实机结果

2026-11-23 在上传和启动前两次确认 `192.168.10.12` 的内核为
`5.10.201-1.el7.x86_64`，使用本轮最新统一 LRU 源码 clean 构建的二进制，
核对本地与目标文件 SHA256 一致后，分别运行 peer ID 开启、关闭测试。
未使用历史 `115a012` 或切换内核前的旧二进制。

| 用例 | 开启 | 关闭 |
| --- | --- | --- |
| IPv4 双 peer，反序响应 | 两个独立 ID，各自双向序号 0、1 | 共享物理 ID |
| IPv6 同 IP、不同端口双 peer | 两个独立 ID，各自双向序号 0、1 | 共享物理 ID |
| wildcard 本地地址不完整 | 回退物理 ID | 保持物理 ID |
| connected UDP 同 peer `sendmmsg` 两条 DNS 后继续 `sendmsg` | 同一 peer ID，序号 0、1、2 | 保持原输出行为 |
| TCP HTTP 请求/响应 | 同一服务端物理 ID | 同一服务端物理 ID |
| Peer Map 类型 / 容量 | `lru_hash` / 40960 | `lru_hash` / 1 |
| `socket_info_map` 与输出 ID 对比 | Map 仍为物理 ID，未被 peer ID 覆盖 | 输出 ID 等于物理 ID |

两种模式均通过，实际加载的均为 `socket-trace-bpf-linux-common`。
5.2+ 在 `df_T_exit_write` 仍返回 `E2BIG (errno 7)`，随后由现有加载器回退
common，与初版记录一致；本轮不将此记录为 5.2+ 加载通过。
DNS 测试端口仅写入本次 tracer 自己的端口 bitmap，不修改其他进程配置。

结束后确认无新增 BPF Map、Program 或 kprobe 残留，sysctl、原控制 socket、
控制程序及日志文件均恢复。未做 KPROBE_ONLY 专项实测；不同 peer、不等长或
部分成功的 mmsg、Linux 4.14/4.19、KFUNC/fentry 及当前统一 LRU 实现在
3.10 内核上的完整 tracer 加载和数据采集均不在本轮实测结论内；上述用户提供
的 EL7 3.10 Map 能力验证单独记录，不扩展为完整 tracer 验证通过。

切核前曾在 3.10 上测试带普通 Hash 分支的中间快照；其源码、二进制和结果
单独保存在 `hash-map-snapshot/`，不混入上述统一 LRU 的 5.10 验证结果。

### 本轮构建追溯

- 构建时源码基线：`4f91668c9c77a062a3a642842f9bdd95f0a17c7e` 加当时工作区中的本轮修改，包括统一 LRU 的改动；该基线提交号不包含本轮修复。
- 二进制 SHA256：`34ae8fa409c94c5a61af545ebdb4e447a0018f8269be0db553043fd1f40e89cf`。
- 本机归档：`/home/jiping/deepflow/deepflow-1/udp-peer-insn-validation-20261123.3B06Cj`。
- 归档内 `socket_tracer` 为本轮实测文件；构建日志为 `current-lru-build-and-test.log`。
- `source-changes.patch`、`changed-source-sha256.txt`、`instruction-counts.log`、`binary-provenance.log` 保存源码和嵌入 ELF 校验信息。
- `target-validation-5.10-command.log`、`runtime-results.json`、`tracer-on.log`、`tracer-off.log` 保存本轮 5.10 原始记录。

## 2026-11-23：5.2+ ELF 的 E2BIG 排查

目标是在 `192.168.10.12` 的 `5.10.201-1.el7.x86_64` 上实际加载
`socket-trace-bpf-linux-5.2_plus`，不再把回退 common 记为该变体通过。
不新增 tail call，不降低 18-iovec 上限，也不降低 HTTP2 扫描上限
（5.2+ / KFUNC 为 8，common 为 5）。

仅在独立实验源码的加载器中开启 verifier 诊断，原始失败为：

```text
program=df_T_exit_write errno=7
BPF program is too large. Processed 1000001 insn
stack depth 384
processed 1000001 insns (limit 1000000)
max_states_per_insn 37 total_states 51737 peak_states 13791
```

这里触及的是 verifier 对不同路径累计检查的 100 万条指令上限，
不是 common 的单程序静态 4096 条限制；两项检查必须分别验证。
实验同时涉及协议推断和后续输出复制路径，不能只根据最后失败位置
认定是某一个协议的静态指令数超限。诊断加载器不作为生产修复提交。

排查还发现 `sendmmsg` / `recvmmsg` 退出处理使用
`sizeof(args->msg_len)`：该字段是 `unsigned int *`，在本次 x86_64
环境中读了 8 字节，而 `mmsghdr.msg_len` 只有 4 字节。
当前改为初始化为零的 `__u32 bytes_count`，只读取 `sizeof(bytes_count)`；
读取失败时保持零，不提交数据。新增测试直接提取两个真实退出处理函数，
检查相邻字段污染、无符号扩展、读取失败及退出状态非正时的清理行为。
该长度修正本身没有解决 E2BIG，不能据此宣布 5.2+ 加载通过。

实验归档：`/home/jiping/deepflow/deepflow-1/udp-peer-e2big-validation-20261123.xuoXU6`。
其中 `diagnostic-tracer-on.log` 保存原始 verifier 统计；失败候选的日志和
二进制单独保留，不与最终验证混用。

### 采用的状态归并方案

仅对 `LINUX_VER_5_2_PLUS` 的直接调用路径增加以下处理：

1. 在既有 per-CPU `ctx_info` 的空闲联合体空间保存、volatile 读回完整
   64 位 `bytes_count`，避免不同系统调用入口带来的长度范围约束在后续路径中
   反复展开。真实长度不截断，不新增 Map，也不保存 UDP 历史端点。
2. 协议推断前，用 `bpf_probe_read_kernel` 原址读回 `conn_info` 的标量区域，
   读取范围止于 `socket_info_ptr` 之前，保留该 Map Value 指针的 verifier 类型。
3. 输出前再原址读回连接状态；先保存、随后恢复有类型的 `socket_info_ptr`，
   避免把它变成不可解引用的普通整数。任一次读取失败都停止本次提交。

这些处理让 verifier 在阶段边界重新处理未知标量，而不是继续携带推断阶段的
细分状态；运行时保留原数值及连接状态。没有把完整连接状态搬到 Map 后直接
解引用其中的指针，也没有增加 BPF-to-BPF 调用、tail call 或新的加载回退规则。

`ctx_info` 的推断缓冲仍从偏移 0 开始，长度 scratch 不覆盖推断缓冲，联合体总
大小仍等于原 `tail_calls_context` 大小；测试编译真实结构定义验证这些布局约束。
common、3.10 和 KFUNC 不执行新增状态归并逻辑。协议推断实现、线程协议缓存、
原 iovec 复制循环及其 18 项上限全部保留，HTTP2 仍扫描 8 / 5 帧。

新增契约测试执行真实状态归并代码，覆盖完整 64 位长度值、空和非空 Map 指针、
连接状态逐字节不变、推断缓冲不被覆盖、读取失败，以及 common / KFUNC 不进入
新增路径。另有真实 HTTP2 推断代码测试覆盖扫描边界、角色、padding、priority、
prestore、端口过滤和线程缓存路径保留。

方案每次进入对应阶段会增加读取 helper 调用；本轮不宣称零性能开销，也未做
生产流量的吞吐、CPU 或丢包率基准测试。

### 诊断候选的 5.10 验证

保留原 iovec 复制循环的候选 `count-map-original-iov` 已实际加载 5.2+ ELF，
全部 81 个程序通过 verifier，无 common 回退。记录如下：

| 程序 | 累计检查指令数 |
| --- | ---: |
| `df_T_exit_write` | 592373 |
| `df_T_exit_sendmsg` | 856093 |
| `df_T_exit_sendmmsg` | 853184 |
| `df_T_exit_recvmmsg` | 853184 |
| 全部程序最大值 | 856093，低于 1000000 |

开启、关闭 peer ID 两种模式均完成 IPv4 / IPv6 双 peer、wildcard 回退、
connected UDP `sendmmsg`、TCP HTTP1、HTTP2 第 8 帧 HEADERS 和
18-iovec `sendmsg` 用例；最后一项同时核对完整 payload 与 `LEN/SYSCALL_LEN`。
sendmmsg / recvmmsg 的 `msg_len` 邻接 padding 写入非零值，验证输出长度没有
被高 4 字节污染。

补充的 connected UDP `recvmmsg` 用例一次成功接收两条等长消息，再继续
`recvmsg`。v6.6 原入口只保存第一条的 iovec，未保存第二条，因此预期采集的是
第一条和后续 `recvmsg`，两条事件在开启模式下序号为 0、1。本轮明确保留这一
既有能力边界，不把它记为 recvmmsg 全批次采集，也不扩展不同 peer、不等长或
部分成功的 mmsg 支持。

两种模式实际 Map 类型均为 LRU Hash，容量分别为 40960 / 1；`socket_info_map`
仍保留物理 ID。结束后无新增 Map、Program 或 kprobe，sysctl、原控制 socket、
控制程序及日志均恢复。原加载器已恢复，最终无诊断二进制的 clean 构建及
复测结果见下节，不用诊断候选代替最终验收。

### 最终 clean 构建与无诊断复测

在同一个独立源码副本、同一构建镜像中恢复生产版 `user/load.c`，核对工作区
与构建副本的内核源码、加载器及测试一致，再执行：

```bash
make clean
make socket-tracer
make test
make -C kernel PREFIX=common-arm64 ARCH=arm64 C_USE_STATIC=0
```

上述命令全部通过。镜像内没有 `python3`：首次构建脚本在这四个命令之后的
额外 Python 3 检查处停止，并非构建或 `make test` 失败。随后修正辅助脚本的
解释器可用性检查，在镜像内补跑 Python 2，并在验证宿主机明确分别运行
Python 2、Python 3 的全部四组契约测试，两种解释器各 9 项全部通过。
没有替换 Cargo 锁定版本、跳过原生测试或放宽 4096 条检查。

| 检查 | 最终结果 |
| --- | --- |
| common、3.10、5.2+、KFUNC、Kylin、RT、KPROBE | 七变体 clean 编译及最终二进制嵌入校验通过 |
| `make test` | 原生测试及四组契约测试通过 |
| common / 3.10 / Kylin / RT / KPROBE | 全部函数最多 4083 条；两个 output 各 4080 条 |
| 5.2+ / KFUNC 静态最大指令数 | 分别为 25323 / 25230；不把它们记为满足旧内核 4096 条上限 |
| ARM64 定义的 common | 编译、Map 布局和静态指令检查通过；最大 4083 条，未做 ARM64 实机测试 |
| 各变体 UDP Map | 均为 LRU Hash，key=48、value=16、max_entries=40960 |
| 与此前统一 LRU 构建比较 Map 定义 | 全部相同；5.2+ / KFUNC 各 32 个，其他各 31 个；`ctx_info` value 始终为 248 字节 |
| Python 2 / Python 3 | 各 9 项通过，含 mmsg 长度、状态归并、HTTP2 边界及 UDP 元数据回归 |
| `git diff --check` | 通过 |

将最终 `socket_tracer` 上传至同一测试目录，启动前再次校验内核和本地、远端
SHA256 一致，再运行 peer ID 开启、关闭两轮：

```text
KERNEL=5.10.201-1.el7.x86_64
SHA256=832bf953339173560517c8bc254d19be94791432ca0cb23ca52df38dbfbff1fa
READY on socket-trace-bpf-linux-5.2_plus
PASS on
READY off socket-trace-bpf-linux-5.2_plus
PASS off
```

两轮均实际加载 `socket-trace-bpf-linux-5.2_plus`，日志中没有 common 回退或
E2BIG。完整执行了上述功能用例；18-iovec 请求完整采集 72 字节，`LEN` 与
`SYSCALL_LEN` 均为 72；第 8 帧 HEADERS 的 HTTP2 请求、响应双端共 4 条事件
均被识别。最终退出后无新增 Map、Program 或 kprobe，所有记录的 sysctl、
控制 socket、原控制程序与日志均恢复。

当前测试机仍为 5.10；统一 LRU 的 3.10 完整 tracer 加载及数据采集没有在本轮
重新验证。Linux 4.14 / 4.19、KFUNC/fentry、KPROBE_ONLY 专项、实际 ARM64
内核和生产负载性能也不在本次实机结论内。3.10 支持依据仍仅为前述具体 EL7
内核的用户提供 Map 能力验证及本轮静态编译检查，不扩展到全部 3.10 内核。

### 最终追溯文件

- 构建时源码基线：`4f91668c9c77a062a3a642842f9bdd95f0a17c7e` 加当时工作区中的本轮修改；不把基线提交号当作本次产物的独立编译提交号。
- 本机归档：`/home/jiping/deepflow/deepflow-1/udp-peer-e2big-validation-20261123.xuoXU6`；其中 `socket_tracer` 为最终实测的无诊断二进制。
- `final-clean-build-and-test.log` 保存 clean 构建、原生测试、ARM64 编译及解释器缺失记录；`final-container-python-contracts.log` 和 `final-python2-python3-contracts.log` 保存补跑结果。
- `final-instruction-counts.log`、`final-map-layout-comparison.log`、`final-binary-provenance.log` 保存真实 ELF、Map 布局及最终嵌入校验。
- `final-target-command.log`、`final-runtime-results.json`、`final-tracer-on.log`、`final-tracer-off.log` 保存最终实机结果及清理检查。
- `source-changes.patch` 包含新增测试，`changed-source-sha256.txt`、`final-source/` 保存构建验证时的源码和文档快照；修复代码、契约测试及验证文档一并提交，具体提交号以 Git 记录为准。

## 2026-11-23：ARM64 Go TLS 入口编译栈超限

### 复现与原因

以 `59155017d675c203b5c7efaee4242f7885dc1ecf` 为源码基线，使用 Clang/LLVM
11.0.0，在独立副本中分别检查 x86_64 与真实 AArch64 前端的 BPF 编译结果。
x86_64 可编译，但 `df_U_go_tls_read_exit` 的最大栈负偏移已达 504 字节。
使用 AArch64 target triple 和独立 ARM64 sysroot 后，原提交复现同一入口的
512 字节栈超限，诊断行同样落在 `protocol_inference.h:2678`、`2601`、`2599`。
这是 LLVM 生成 BPF 字节码时的编译失败，不是运行时 verifier 的 E2BIG。

此前仅通过 `ARCH=arm64` 更改 `__TARGET_ARCH_arm64` 宏的检查，Clang 默认
target triple 仍为 x86_64；不能把它当作真实 ARM64 前端的编译覆盖。本轮采用
`--target=aarch64-linux-gnu`，并使用独立提取的 Debian ARM64 交叉头文件
（glibc 2.31、Linux UAPI 5.10.13），不修改宿主机系统头文件。
这仍是交叉编译验证，不是原生 ARM64 CI 镜像或 ARM64 实机加载验证。

复现命令如下；在原提交副本中失败，在修复副本中通过：

```bash
make -C agent/src/ebpf/kernel \
    PREFIX=arm64-cross ARCH=arm64 LINUX_VER_5_2_PLUS=1 C_USE_STATIC=0 \
    CLANG="/usr/bin/clang --target=aarch64-linux-gnu \
        --sysroot=$ARM64_SYSROOT \
        -isystem $ARM64_SYSROOT/usr/aarch64-linux-gnu/include" \
    build/arm64-cross/socket_trace.bpf.elf
```

### 最小修复

仅在 `kernel/go_tls.bpf.c` 的 Go TLS read 退出入口中，为 HTTP2 TCP 序号
Map 更新的 `tcp_seq_key`、`tcp_seq` 增加独立局部作用域，使 LLVM 能在后续
协议推断前复用这两个地址曾被传给 helper 的临时变量所占栈槽。

- Map key/value、4 字节 TCP 序号读取方式、`BPF_NOEXIST` 和调用顺序均不变。
- 不新增 Map、helper 调用、tail call 或运行时分支，不更改 Map 布局。
- 不撤回既有 5.2+ 状态归并和 LRU 修复，不降低 18-iovec、HTTP2 8/5 帧上限。
- 不修改 `protocol_inference.h`，报错所在的 Pulsar 推断逻辑保持原样。
- 修复后同一 Go TLS read 入口的最大栈负偏移为 x86_64 480、ARM64 488 字节。

新增 `test_go_tls_read_sequence_scratch_scope`，检查临时变量确实处于独立作用域，
并提取真实更新代码和真实 key 定义执行原生测试，覆盖 TCP 序号高位、零值及
回绕边界。原提交先验证该回归测试失败，再应用修复验证通过。

### 本轮验证结果

| 检查 | 结果 |
| --- | --- |
| x86_64 `make clean`、`make socket-tracer`、`make test` | 全部通过，七变体 ELF 均确认嵌入最终二进制 |
| ARM64 common / 3.10 / 5.2+ / Kylin / RT / KPROBE | AArch64 前端及独立 sysroot 编译通过 |
| ARM64 KFUNC | 补充交叉环境的标准头文件预包含后编译通过，见下文限制 |
| 双架构旧内核变体的指令数 | 各变体所有程序最多 4083 条，未放宽 4096 条检查 |
| 双架构全部七变体的栈负偏移 | 所有程序均小于 512 字节，最大 488 字节 |
| Map 定义比较 | 双架构均与上一轮各自对应变体的 Map 定义逐字节一致 |
| x86_64 程序字节码比较 | 七变体中均仅 `df_U_go_tls_read_exit` 改变，其他函数逐字节一致 |
| Python 2 / Python 3 | 四组契约测试分别共 10 项全部通过 |

ARM64 sysroot 的 KFUNC 编译最初因未间接包含 `stdint.h` 而缺少
`uintptr_t`。仅为该交叉编译命令的 `CLANG` 参数追加 `-include stdint.h` 后
通过，没有修改生产头文件或 Makefile。该结果不能替代原生 ARM64 CI 镜像验证。
本轮测试依赖沿用此前未变的 trace-utils 静态库及离线 Cargo 缓存；eBPF 和
socket_tracer 仍执行上述 clean 构建，原生测试没有跳过。

在 `192.168.10.12` 的 `5.10.201-1.el7.x86_64` 上上传最终二进制，校验本地、
远端 SHA256 一致后，重新执行 peer ID 开启、关闭两轮：

```text
SHA256=7ce00e1e6135a32103e61b9b70f7d0b2fa33a749e6f44d4a157f99446182bcd7
READY on socket-trace-bpf-linux-5.2_plus
PASS on
READY off socket-trace-bpf-linux-5.2_plus
PASS off
```

两轮均实际加载 5.2+ ELF，没有 E2BIG 或 common 回退。IPv4 / IPv6 双 peer、
wildcard、sendmmsg、此前明确的 recvmmsg 首条采集边界、TCP HTTP1、HTTP2
第 8 帧 HEADERS、18-iovec 完整 72 字节采集均通过。清理检查确认没有新增
Map、Program、kprobe，sysctl、原控制 socket、控制程序及日志均恢复。

Go TLS 入口本轮覆盖编译、原生序号更新测试及 5.2+ ELF 整体加载；未执行
真实 Go TLS HTTPS 会话。没有 ARM64 实机、3.10 / 4.14 / 4.19 实机、
KFUNC/fentry 实机或生产流量性能测试，不扩大已有功能验证结论。

### 本轮追溯文件

- 构建时源码为 `59155017d675c203b5c7efaee4242f7885dc1ecf` 加本节作用域修复；不能把未加修复的基线提交单独当作最终二进制的编译来源。
- 本机归档：`/home/jiping/deepflow/deepflow-1/udp-peer-stack-validation-20261123.Nknsqw`，其中 `socket_tracer` 为本轮实测文件。
- `baseline-arm64-cross-build.log` 保存原提交的实际复现；`candidate-seq-scope-arm64-build.log`、`final-arm64-*-build.log` 保存修复后交叉编译结果。
- `final-clean-build-and-test.log`、`final-python-contracts.log`、`final-binary-provenance.log` 保存 clean 构建、测试及嵌入 ELF 校验。
- `final-elf-inspection.log`、`final-elf-results.json` 保存双架构指令数、栈偏移、Map 定义及逐函数字节码比较结果。
- `final-target-command.log`、`final-runtime-results.json`、`final-tracer-on.log`、`final-tracer-off.log` 保存最终 5.10 实机测试和清理结果。
- `source-changes.patch`、`changed-source-sha256.txt`、`final-source/` 保存本轮代码、回归测试及验证文档快照。
