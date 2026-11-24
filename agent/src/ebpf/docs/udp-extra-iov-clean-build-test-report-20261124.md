# EXTRA_LOOP_LIMIT=8 清理构建复测

2026-11-24，针对“修改为 8 后，最终 sample 是否仍嵌入旧变体”的疑问，
从提交 `a54fbe14005a2def0bd1dee8bbb47986bcc6d33f` 导出源码，执行 `make clean`，
重新生成七种 socket 字节码、构建 C 库和 Rust socket tracer，并核对最终二进制。

**七个变体均已重新生成并嵌入新 sample；同一份新 sample 已在 4.14 / common、
4.19 / common 和 5.10 / 5.2+ 上完成隔离开关两轮复测，120 条发送事件全部通过。**

## 构建与字节码核对

构建在 `10.50.5.27` 的新独立目录进行，使用
`hub.deepflow.yunshan.net/public/rust-build:1.31`、Clang/LLVM 11.0.0 和 devtoolset-11。
eBPF 源码保持提交中的 `EXTRA_LOOP_LIMIT=8`、`LOOP_LIMIT=18`。
内核源码 SHA256 与当前提交一致：

```text
3f16c77e5899e81f0ddaa80995fae388c2616f684fdf98faeb58412bffff4fa8
```

验证过程：

1. 执行 `make clean`，日志保存为 `make-clean.log`。
2. 清理后检查 `kernel/build`、七个 `user/socket_trace_bpf_*.c`、`libtrace.a`、
   `staticobjs`、`.socket-tracer` 和 sample 的 `target` 均不存在，保存 `clean-audit.json`。
3. 执行 `make socket-tracer`，七个变体均出现新的 BPF 编译及 C 数组生成记录，C 库重新构建。
4. 首次 Rust 构建因源码导出缺少 workspace 上下文失败；从同一提交补齐 agent 源码后，
   重新执行 `make socket-tracer` 成功，最终日志为 `make-socket-tracer-complete.log`。
5. 对七个变体逐个解码 C 数组，检查其与新 ELF 逐字节一致；再检查完整 ELF 确实包含于
   最终可执行文件，并确认 ELF、C 数组生成时间晚于清理检查。

第 5 步的全部断言通过，结果保存在 `binary-provenance-clean.json`。
common 的 TP/KP 输出程序均为 3163 条静态指令；5.2+ 的 `exit_recvmmsg` 为 20320 条，
与本次 8 项路径相符。

| 变体 | 清理后重新生成 | C 数组与新 ELF 一致 | 新 ELF 已嵌入 sample |
| --- | --- | --- | --- |
| common | 是 | 是 | 是 |
| 3_10_0 | 是 | 是 | 是 |
| 5_2_plus | 是 | 是 | 是 |
| kfunc | 是 | 是 | 是 |
| kylin | 是 | 是 | 是 |
| rt | 是 | 是 | 是 |
| kprobe | 是 | 是 | 是 |

本轮 sample 只增加 `UDP_IOV` 完整载荷日志、隔离开关环境变量和日志路径环境变量；
临时差异保存在 `sample-instrumentation.patch`。未复用之前 sample 的其他临时功能调整。
jattach 依赖源码复用已有副本，清理其旧产物后重新构建；Rust 沿用此前离线依赖解析，
锁文件差异保存为 `Cargo.lock.offline-resolution.patch`，详见
[首次构建报告](udp-extra-iov-limit-test-report-20261124.md)。
这些测试副本调整未写回生产源码。

## 新二进制实际运行

三个内核运行环境使用同一个新构建的 `socket_tracer-clean-8`，SHA256 均为：

```text
c101a9bf85063416cd7918fe268ecfd9ff8e9da4ccfa5c1f1bf0cdbb00dd9f44
```

每轮严格检查预期变体的加载成功日志和 `TRACER_RUNNING`，避免将自动回退误计为成功。

| 内核 / 变体 | 节点 | 隔离关闭 | 隔离开启 |
| --- | --- | --- | --- |
| 4.14.15-1.el7.elrepo.x86_64 / common | 10.50.5.29（切回 4.14 后） | 20/20 通过 | 20/20 通过 |
| 4.19.17-1.el7.x86_64 / common | 10.50.5.27 | 20/20 通过 | 20/20 通过 |
| 5.10.201-1.el7.x86_64 / 5.2_plus | 10.50.5.29 | 20/20 通过 | 20/20 通过 |

使用提交中的 `test_sendmmsg_iov.py --limit 8`，每种模式运行 10 个真实 DNS A + AAAA 场景。
覆盖 1/2/4/8 段、首个及中间 iovec 为空、第一条消息分为 4 段，以及第二条消息 9 项时
按前 8 项截断。对接收端完整载荷、采集端载荷或预期前缀、`cap_len`、`syscall_len`、
稳定 ID、批内相邻序号逐项核对；隔离开启时再检查全部 peer 序号为 0–19。

本轮已核对的 **120 条发送事件全部通过**。各轮控制工具、sysctl、kprobe 定义均已恢复；
`cleanup-audit.json` 通过 BPF ID 枚举确认没有遗留 program 或 Map。

## 归档与验证范围

构建及 Linux 4.19 运行归档：

```text
/home/jiping/deepflow/deepflow-1/udp-extra-iov-clean-20261124.EkN0he
```

Linux 5.10 运行归档：

```text
/tmp/udp-extra-iov-clean-20261124.KCmxX1
```

`10.50.5.29` 随后切回 4.14，使用相同新二进制完成两轮复测，另存日志，未覆盖 5.10 结果。
Linux 4.14 运行归档：

```text
/tmp/udp-extra-iov-clean-4.14-20261124.ZxFFm4
```

本地归档：

```text
C:\Users\Yunshan\AppData\Local\Temp\udp-extra-iov-20261124\clean-build
```

归档保留源码包、构建命令和日志、清理检查、字节码嵌入核对、运行脚本、逐事件预期、
实际采集日志和恢复审计。KFUNC 等其他变体本轮仅编译和核对嵌入，未执行运行验证。

三个内核的结果均来自本次清理构建后实际运行；未用此前定向重编译的测试结果替代。
综合本轮结果，统一保留 `EXTRA_LOOP_LIMIT=8`，第一条消息的 `LOOP_LIMIT=18` 不变。
