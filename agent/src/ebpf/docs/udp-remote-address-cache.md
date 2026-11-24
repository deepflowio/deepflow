# v6.6：停用 UDP 历史远端地址缓存

## 问题与范围

未 connect 的 UDP socket 可以在同一个 FD 上接收不同客户端的数据，远端地址是单个报文的属性，不能作为该 socket 的固定状态保存。

原先 v6.6 在创建 `socket_info_map` 项时保存一次 UDP 远端 IP 和端口；后续事件无法取得远端端口时，可能读取这份历史地址并用于当前报文。这会把其他客户端的报文错误归到之前的客户端。

本次在 `v6.6` 上仅停用这套缓存机制，基线提交为 `92d1db5706627ae2aff655ab38d13e42247839e6`，不整体 cherry-pick 上游 `f717703d`，避免引入该提交中的其他 syscall 改动。

## 修改内容

- 删除 `__data_submit()` 中向 `socket_info_map` 保存 UDP 远端 IP、端口和有效标志的逻辑。
- 删除 `process_data()` 中从 `socket_info_map` 回填历史远端 IP、端口的逻辑，不再用历史值修改当前 `data_args_t`。
- 保留原位置的 `reserved_udp_addr_cache`、`reserved_udp_addr`、`reserved_udp_port`，维持 Map value ABI。
- 保留 `socket_info_map` 本身及其协议推断、序号、追踪状态等用途；不删除这些用途需要的 Map 查询。
- 保留原有从内核 socket 获取地址、从当前 syscall 参数提取地址的路径，以及 UDP mmsg 序号处理。

在 x86_64 上核对修改前后的 `socket_info_s` 大小均为 82 字节；`seq`、`prev_data`、`correlation_id`、`peer_fd`、`trace_id`、`uid` 等字段的偏移保持不变。回归检查包含这些布局断言。

## 行为变化

- 当前 syscall 能提供 peer 地址时，继续按 v6.6 现有路径使用该地址，不保存供后续报文复用。
- connected UDP 仍保留从内核 socket 获取远端地址的能力。
- 对于未 connect UDP，若内核 socket 和当前 syscall 都没有可用远端地址，则保留未知/零地址，不再套用上一报文的客户端地址。例如 `read`、`readv` 等不返回源地址的读取路径可能出现这种情况。
- 本次不补全 v6.6 原有的 mmsg 地址采集缺口，也不包含 sockaddr 长度检查、双栈地址解析、UDP peer socket ID 隔离或 tail-call 改造。

## 验证方法

新增回归检查并接入 `agent/src/ebpf/test/Makefile`：

```bash
make -C agent/src/ebpf/test test_udp_peer_cache_contracts
```

检查项包括：

1. 内核源码中不再读写旧 UDP peer 缓存字段。
2. ABI 占位字段仍然存在。
3. 提取真实 `process_data()` 端口选择代码并编译执行：不同 syscall 端口独立生效，无地址时保持零端口，内核已有的 connected UDP 端口及 TCP 端口不受影响。
4. 编译并断言真实 `socket_info_s` 的大小与关键字段偏移。

该回归在修改前失败、修改后通过，Python 3 和 Python 2 解释器均验证通过。它是源码契约及提取代码检查，不等同于实机 eBPF 加载或多客户端 UDP 数据面测试。

编译环境参考原 `v6.6-udp-chat-recovery-20261119.md`：使用 `hub.deepflow.yunshan.net/public/rust-build:1.31` 容器和 `devtoolset-11`，以 LLVM 11 编译。仓库只读挂载，ELF 输出到独立空目录，不在现有工作区执行 `make clean`，也不复用既有 ELF。

## 2026-11-20 验证结果

- 宿主机 Python 3、Python 2，以及上述构建容器中的回归检查均通过，每轮执行 3 项检查。
- 七种 socket trace eBPF 变体从空输出目录编译通过：`common`、`3_10_0`、`5_2_plus`、`kfunc`、`kylin`、`rt`、`kprobe`。
- 实际工具链为 GCC 11.2.1、Clang/LLVM 11.0.0。
- `git diff --check` 和新增文件的空白检查通过。
- 编译前后的两个内核源文件 SHA256 一致，确保验证期间没有替换被编译的实现。

构建日志、源码摘要、ELF 摘要、回归日志及修改源码归档位于：

```text
/home/jiping/deepflow/deepflow-1/udp-no-peer-cache-validation-20261120.5b3yja
```

## 验证边界

本轮未重新构建完整 Rust `socket_tracer`，未在 `192.168.10.12` 运行 `socket_tracer`；不能引用此前其他提交的 4.19/5.10 测试作为本改动的实机验证结果。

## 2026-11-24 后续实机复测

PR #11970 的 `9dcf0f28c3da94bcdef59b2e08448f9766defad5` 已包含本修改，
该 HEAD 重新 clean 构建的 `socket_tracer` 已在 `192.168.10.12` 的
`5.10.201-1.el7.x86_64` 上测试。除 IPv4 / IPv6 多客户端外，补充了同一服务端
先通过 `recvmsg` 获取客户端 A 地址，再通过不返回地址的 `recv` 接收客户端 B
的用例：第二次输出远端为 `0.0.0.0:0`，不复用 A 的历史地址。
UDP peer 隔离开启、关闭和默认三种模式均通过。

完整提交覆盖矩阵、编译来源、实测 SHA256、并发检查和验证边界见
[`udp-peer-id-v6.6.md`](udp-peer-id-v6.6.md) 的“2026-11-24：PR #11970 最新 HEAD 全范围复测”。
这里的后续结果不扩大为 3.10 / 4.14 / 4.19 或 KFUNC 实机验证通过。
