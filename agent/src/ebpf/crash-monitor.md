# Crash Monitor 设计说明

## 1. 背景与目标

DeepFlow Agent 的 eBPF 用户态运行时包含大量直接与内核、ELF、符号表、profiling 逻辑交互的 C 代码路径。这些路径一旦触发 `SIGSEGV`、`SIGBUS`、`SIGABRT`、`SIGILL`、`SIGFPE` 等 fatal signal，进程通常会立即终止；如果没有额外保护，留给排障的往往只有一条粗粒度的系统崩溃信息。

crash monitor 的目标不是“吞掉崩溃”或“让损坏后的进程继续运行”，而是：

1. **保留原始崩溃语义**：进程最终仍按原始 fatal signal 退出。
2. **在最危险的时刻只做最小保全**：fatal signal handler 只抓取有界、固定大小的原始机器状态。
3. **把复杂分析延后到正常上下文**：ELF、DWARF、build-id、文件行号恢复等工作全部放到下次正常启动时执行。
4. **覆盖 C/eBPF 工作线程**：不仅是初始化线程，所有接入 monitored helper 的线程都要准备自己的 altstack。
5. **适应容器持久化**：崩溃快照固定落盘到 `/var/log/deepflow-agent/deepflow-agent.crash`，便于挂载、收集与离线分析。

相关源码入口：

- 快照 ABI：`agent/src/ebpf/user/crash_monitor.h`
- Stage-1/Stage-2 主实现：`agent/src/ebpf/user/crash_monitor.c`
- Stage-2 符号化器：`agent/src/ebpf/user/crash_symbolize.c`
- ELF helper：`agent/src/ebpf/user/elf.c`
- 启动接线：`agent/src/ebpf/user/tracer.c`
- 构建接线：`agent/src/ebpf/Makefile`

---

## 2. 核心设计原则

### 2.1 严格的两阶段边界

整个机制严格分为两个阶段：

- **Stage-1：fatal signal context**
  - 目标：保住原始现场。
  - 只做寄存器抓取、有限栈回溯、模块元数据复制、二进制快照写盘。
  - 不做 ELF/DWARF 解析，不做 `/proc` 扫描，不做复杂日志格式化。

- **Stage-2：normal process context**
  - 目标：消费旧快照并输出可读崩溃报告。
  - 允许打开 ELF、读取 debuginfo、遍历 DWARF、打印函数名与 `file:line`。
  - 允许使用常规日志、文件读写和库调用。

这两个阶段之间通过固定大小的 `struct crash_snapshot_record` 作为 ABI 契约连接。

### 2.2 不在 handler 中做不安全工作

fatal signal handler 运行在最不可信的时刻。此时：

- 当前线程的普通栈可能已经损坏；
- 堆状态可能不一致；
- 进程中的锁可能处于未知状态；
- libc / runtime 的内部状态也可能不再可靠。

因此 handler 中明确避免：

- `malloc/free`
- 锁和复杂同步原语
- `stdio` 风格复杂格式化
- `/proc/self/maps` 扫描
- ELF / DWARF 解析
- 常规日志路径
- 任何需要假设“进程状态仍然一致”的复杂操作

### 2.3 best-effort，而不是 all-or-nothing

无论 Stage-1 还是 Stage-2，都采用 **best-effort** 策略：

- 某一帧无法识别模块，不影响其他帧；
- 某个模块找不到 debuginfo，不影响其余模块；
- 某一帧没有 DWARF 行号，也仍然可以输出 symbol 或 raw PC；
- 即使所有帧都无法完整符号化，崩溃摘要和原始地址仍然会被输出。

### 2.4 保留原始崩溃语义

crash monitor 是**诊断工具**，不是恢复工具。handler 在写完快照后会恢复默认信号行为并重新抛出原始 signal，确保：

- 进程退出原因仍是原始 fatal signal；
- core dump、容器状态、supervisor 行为仍符合系统预期；
- 不会因为“捕获崩溃”而掩盖未定义行为。

---

## 3. 总体架构

### 3.1 Stage-1 的前置准备（正常上下文）

虽然 Stage-1 的核心执行点在 fatal signal handler 中，但为了满足 signal-safety 约束，很多准备工作必须在进程**尚未崩溃**时完成：

1. 打开固定快照文件；
2. 安装 fatal signal handler；
3. 为当前线程准备 altstack；
4. 读取 `/proc/self/maps`，预缓存可执行 file-backed mappings；
5. 记录 `/proc/self/exe` 对应的主程序路径；
6. 为每个缓存模块预读取 GNU build-id（若存在）。

这些预处理让 handler 在崩溃当下只需要做“复制固定数据 + 写盘”，而不需要临时发现模块布局。

### 3.2 Stage-1 的崩溃捕获（fatal signal context）

fatal signal 到来后，handler 在 altstack 上执行，主要完成：

1. 从 `siginfo_t` 读取 `si_code`、`si_addr` 等故障信息；
2. 从 `ucontext_t` 提取寄存器：`ip/sp/fp/lr/args[]`；
3. 基于 frame pointer 做有界回溯；
4. 将预缓存的 `modules[]`、`modules_count`、`executable_path` 复制到 record；
5. 为每个 frame 填充：
   - `absolute_pc`
   - `module_index`
   - `rel_pc`
6. 通过 `write()` 追加写入固定大小的 `struct crash_snapshot_record`；
7. 重新抛出原始 signal。

### 3.3 Stage-2 的恢复与符号化（正常上下文）

下次进程正常启动时，启动流程会先消费旧快照，再初始化新的 crash monitor。Stage-2 的职责是：

1. 打开 `.crash` 文件；
2. 逐条读取并校验 record；
3. 输出 crash summary；
4. 对每一帧做模块恢复、ELF 符号解析、DWARF `file:line` 解析；
5. 以 best-effort 方式打印最丰富的可读崩溃报告；
6. `ftruncate()` 清空已经消费的快照文件。

这里需要特别区分两类产物：

- **原始快照**：保存在 `/var/log/deepflow-agent/deepflow-agent.crash`；
- **Stage-2 解析后的最终可读报告**：不会回写到 `.crash`，而是通过现有 eBPF/Agent 日志链路输出到常规运行日志。

也就是说，`.crash` 文件只负责保存结构化原始证据；真正给运维和开发者阅读的“最终报告”会出现在 agent 正常日志里，而不是单独再生成一个新的 crash report 文件。

---

## 4. 启动时序

启动路径中必须保持如下顺序：

1. `crash_monitor_consume_pending_snapshots()`
2. `crash_monitor_init()`

也就是：

- **先消费上一次崩溃留下的旧快照**；
- **再安装本次运行新的 handler 和快照文件**。

这样设计的原因是：

- Stage-2 需要在完全正常的上下文里运行；
- 它会打开文件、校验多条记录、调用 symbolizer、打印格式化日志、清空文件；
- 这些都不应该放进 fatal signal handler。

因此 Stage-2 不是“崩溃当下的一部分”，而是“下一次启动时的恢复流程”。

---

## 5. 快照文件与持久化策略

快照文件固定为：

```c
#define CRASH_SNAPSHOT_FILE "/var/log/deepflow-agent/deepflow-agent.crash"
```

这样做的价值：

1. **与运行日志配置解耦**：crash snapshot 不依赖普通 `log_file` 配置。
2. **适合容器持久化**：`/var/log/deepflow-agent/` 很适合被挂载到宿主机或 sidecar。
3. **便于运维收集**：路径稳定，外部系统更容易采集和归档。

需要注意：

- `.crash` 是**二进制快照文件**，不是普通文本日志；
- 默认语义是“启动时消费并清空”；
- 如果需要保留原始快照做离线分析，应在消费前复制一份。

---

## 6. 快照 ABI 设计

快照 ABI 由 `agent/src/ebpf/user/crash_monitor.h` 定义，核心结构有三个：

- `struct crash_snapshot_module`
- `struct crash_snapshot_frame`
- `struct crash_snapshot_record`

### 6.1 为什么必须固定大小

固定大小 ABI 的好处是：

- handler 不需要构造变长文本；
- 不需要动态分配内存；
- 只需 `memset()` + bounded field fill + `write()`；
- 读取侧可以按固定步长逐条消费；
- `magic/version/size` 可以做强校验；
- 后续演进时可以受控地维护兼容性。

### 6.2 `crash_snapshot_module`

每个模块条目保存一个 executable mapping 的关键信息：

- `start` / `end`：崩溃进程中的运行时虚拟地址范围；
- `file_offset`：该映射起点对应的文件偏移；
- `build_id` / `build_id_size`：GNU build-id；
- `path`：模块路径。

这些字段的用途是让 Stage-2 在原进程已经死亡的情况下，仍能把 raw PC 重新绑定回“崩溃时的真实模块布局”。

### 6.3 `crash_snapshot_frame`

每一帧保存：

- `absolute_pc`：崩溃时的真实运行时地址；
- `module_index`：指向 `modules[]` 的索引；
- `rel_pc`：`absolute_pc - module.start`；
- `reserved`：保留字段。

这里同时保留 `absolute_pc` 和 `(module_index, rel_pc)` 的原因是：

- `absolute_pc` 是最原始、最可信的 fallback 值；
- `(module_index, rel_pc)` 是**跨 ASLR 更稳定**的符号化输入；
- 即使 Stage-2 无法完全解析，也仍可输出 raw PC。

### 6.4 `crash_snapshot_record`

顶层 record 保存：

- `magic/version/size`：格式校验；
- `signal/si_code/pid/tid/fault_addr`：崩溃摘要；
- `ip/sp/fp/lr`：顶层寄存器快照；
- `args[]`：top frame 的 ABI 参数寄存器；
- `executable_path`：主程序路径；
- `modules_count` + `modules[]`：模块元数据；
- `frames_count` + `frames[]`：栈帧数组。

### 6.5 `args[]` 的能力边界

`args[]` 只是 **top frame 的原始 ABI argument registers**，不代表：

- 能恢复所有源码级函数参数；
- 能恢复 older frames 的参数；
- 能恢复 stack-passed arguments；
- 能恢复浮点/SIMD 参数；
- 能在优化后二次映射出源码级参数名。

因此它的定位是“尽力保留顶层寄存器参数现场”，而不是完整参数还原系统。

---

## 7. Stage-1 细节

### 7.1 fatal signal 覆盖范围

当前监控的 fatal signals 包括：

- `SIGSEGV`
- `SIGABRT`
- `SIGBUS`
- `SIGILL`
- `SIGFPE`

handler 安装使用的关键标志：

- `SA_SIGINFO`：让 handler 能拿到 `siginfo_t` 与 `ucontext_t`；
- `SA_ONSTACK`：让 handler 在 altstack 上运行；
- `SA_RESETHAND`：触发一次后恢复默认信号行为，便于 rethrow。

### 7.2 为什么必须使用 altstack

如果线程因为栈损坏、栈溢出、错误栈指针等原因崩溃，再继续在原普通栈上运行 handler，极有可能再次 fault。

因此当前实现会：

- 为当前线程安装独立的 signal altstack；
- 在 worker thread 入口统一调用 `crash_monitor_prepare_thread()`；
- 确保崩溃线程即使普通栈不可用，也仍有机会完成最关键的快照写盘。

需要强调的是：

- `sigaltstack()` 是**线程级属性**，不是进程级属性；
- 主线程装了 altstack，不代表其他线程也装了；
- 所有被纳入覆盖范围的 C/eBPF 线程都必须单独准备。

### 7.3 为什么要预缓存线程真实栈边界

在回溯 frame pointer 链时，约束条件必须基于**被打断线程的普通栈边界**，而不是 `ucontext_t::uc_stack` 中描述的 signal altstack。

因此当前实现会在正常上下文中预缓存线程真实栈边界，供 handler 在回溯时做保守边界检查，例如：

- frame pointer 必须单调前进；
- 必须满足自然对齐；
- 必须落在线程普通栈边界内；
- 达到最大帧数立即停止。

### 7.4 模块缓存如何工作

为了让 Stage-2 在旧进程退出后仍能恢复模块信息，当前实现会在正常上下文中读取 `/proc/self/maps`，缓存一组**可执行、file-backed** 映射，并为每个模块记录：

- 地址范围；
- 文件偏移；
- 模块路径；
- build-id。

随后在 handler 中直接把这些固定大小的缓存复制到 record。这样：

- handler 不需要扫描 `/proc`；
- Stage-2 不需要依赖已经不存在的旧进程地址空间；
- 记录中天然携带“崩溃时真实观察到的模块布局”。

### 7.5 寄存器与栈帧采集

当前实现支持从 `ucontext_t` 中直接提取崩溃瞬间的寄存器现场。

### x86_64

- `RIP -> ip`
- `RSP -> sp`
- `RBP -> fp`
- 参数寄存器：`RDI/RSI/RDX/RCX/R8/R9`

### aarch64

- `pc`
- `sp`
- `x29 -> fp`
- `x30 -> lr`
- 参数寄存器：`x0-x7`

栈回溯采用 frame-pointer walk，而不是 `backtrace()`。这样做的优点是：

- 依赖更少；
- 对崩溃上下文更可控；
- 更容易做严格边界检查。

### 7.6 frame 注释：`absolute_pc`、`module_index`、`rel_pc`

handler 在得到 `absolute_pc` 后，还会为每一帧补充：

- `module_index`：该地址属于哪个缓存模块；
- `rel_pc`：相对于 `module.start` 的偏移。

这一步是 Stage-2 稳定符号化的关键，因为：

- 单靠 `absolute_pc`，下次启动后的新进程无法直接复原旧进程的 ASLR 布局；
- 有了 `module_index + rel_pc`，Stage-2 可以对照 `modules[]` 恢复 file-relative PC；
- 即使模块解析失败，`absolute_pc` 仍是 fallback。

### 7.7 写盘与 rethrow

handler 最终通过打开好的 `crash_snapshot_fd` 调用 `write()` 追加写入一条 record，然后立即重新抛出原始 signal。

这保证：

- 崩溃现场被尽快保留下来；
- 进程仍按原始故障语义退出；
- crash monitor 不会掩盖真实异常。

---

## 8. Stage-2 符号化流程

当前 Stage-2 已不再只是“打印原始地址”，而是具备完整的 best-effort 符号化链路。

### 8.1 入口与消费流程

启动时 Stage-2 会：

1. 打开 `.crash` 文件；
2. 按 `sizeof(struct crash_snapshot_record)` 循环读取；
3. 校验 `magic/version/size`；
4. 对每条合法记录调用 `crash_symbolize_record()`；
5. 读取结束后 `ftruncate(fd, 0)` 清空文件。

如果出现：

- 非法 record：直接丢弃并 warning；
- 截断尾部：打印 truncated warning；
- 文件不存在：视为无待消费快照，直接返回成功。

### 8.2 crash summary

在真正逐帧符号化之前，Stage-2 先打印 crash summary，包含：

- `signal`
- `si_code`
- `pid`
- `tid`
- `executable`
- `ip`
- `fault_addr`
- `frames`

这样即使后续所有帧都无法完整恢复，至少仍能得到一条可读的崩溃摘要。

### 8.3 单帧符号化的恢复顺序

对每一帧，`crash_symbolize_frame()` 的逻辑大致为：

1. 根据 `frame.module_index` 找到对应模块；
2. 计算 `file_offset_pc = module.file_offset + frame.rel_pc`；
3. 打开原始模块 ELF；
4. 使用 PT_LOAD 信息把 file offset 映射回 ELF virtual address；
5. 优先查找 external debuginfo；
6. 若存在 external debuginfo，则优先用其做 symbol 和 line 解析；
7. 若 external debuginfo 不足，则回退到模块本体的 ELF / DWARF；
8. 收集 symbol、`file:line` 等信息；
9. 输出该帧最丰富的表示；
10. 如果任何一步失败，则退回 raw fallback。

### 8.4 external debuginfo 的查找顺序

Stage-2 优先使用 build-id 精确匹配 debuginfo，查找顺序为：

1. `/usr/lib/debug/.build-id/xx/yyyy....debug`
2. `/usr/lib/debug<module>.debug`

其中：

- 如果 snapshot 中带有 build-id，会优先验证 candidate debuginfo 的 build-id 是否匹配；
- 这样可以避免只靠 pathname 造成的误匹配；
- 当 build-id 无法提供时，再回退到 path-based 位置。

### 8.5 ELF symbol 与 DWARF line 的角色分工

Stage-2 同时使用两类信息源：

### ELF symbol

用途：

- 恢复函数名；
- 即使缺少完整 DWARF，也常常还能给出 symbol；
- 代价较低，适合作为第一层命名恢复。

### DWARF line table

用途：

- 恢复源码路径与行号；
- 在可用时提供比单纯 symbol 更强的定位能力；
- 也可以从 DIE/subprogram 中补充更好的函数名。

Stage-2 的实际行为是：

- 尽可能同时获取 symbol 和 `file:line`；
- 若只有 symbol，则输出 `symbol+offset`；
- 若只有 `file:line`，也会输出；
- 二者都缺失时退回 raw frame 日志。

### 8.6 日志降级策略

当前每帧日志的输出层级大致为：

1. `module + rel_pc + symbol + file:line + build_id`
2. `module + rel_pc + symbol + file:line`
3. `module + rel_pc + file:line (+ build_id)`
4. `module + rel_pc + symbol (+ build_id)`
5. `raw pc + module + rel_pc (+ build_id)`
6. `raw pc`

这正是 Stage-2 best-effort 设计的体现：

- 局部失败只降低该帧信息丰富度；
- 不会导致整条快照消费失败；
- 其他帧仍继续输出。

### 8.7 当前输出示意

可能出现的日志形态包括：

```text
Recovered crash snapshot: signal=11 code=1 pid=123 tid=456 executable=/usr/bin/deepflow-agent ip=0x7f... fault_addr=0x0 frames=6
```

```text
Recovered crash frame[0]: pc=0x7f... module=/usr/bin/deepflow-agent rel=0x1234 symbol=foo+0x18 file=/root/project/foo.c:87 build_id=abcd...
```

```text
Recovered crash frame[3]: pc=0x7f... module=/lib64/libc.so.6 rel=0x2a1f0
```

---

## 9. ELF / DWARF helper 能力

为了支撑 Stage-2，当前在 `agent/src/ebpf/user/elf.c` 中已经补充了通用 helper：

- `elf_read_build_id()`：从 ELF note 中提取 GNU build-id；
- `elf_file_offset_to_vaddr()`：把 file offset 映射回 ELF 虚拟地址空间；
- `elf_symbolize_pc()`：从 `SHT_SYMTAB` / `SHT_DYNSYM` 中为 PC 选择最匹配的 symbol。

这些 helper 的作用是把 Stage-2 的符号化逻辑从 `crash_monitor.c` 中拆分出来，使职责更清晰：

- `crash_monitor.c`：负责 snapshot 捕获与消费；
- `crash_symbolize.c`：负责 Stage-2 高层符号化流程；
- `elf.c`：负责通用 ELF/build-id/symbol 基础能力。

---

## 10. 构建接线

当前构建系统已经完成了 crash symbolizer 的接线：

1. `agent/src/ebpf/Makefile` 的 `OBJS` 中包含：
   - `user/crash_monitor.o`
   - `user/crash_symbolize.o`

2. `deepflow-ebpfctl` 显式链接了：
   - `-ldwarf`
   - `-lelf`
   - `-lz`
   - `-lpthread`

3. 现有构建参数继续保留：
   - `-fno-omit-frame-pointer`

其中 `-fno-omit-frame-pointer` 很重要，因为当前 Stage-1 栈回溯显著依赖 frame pointer。如果编译时省略它，回溯深度和可靠性都会受影响。

---

## 11. 线程覆盖策略

当前线程覆盖依赖 monitored helper：

- 在线程真正进入工作函数前，统一调用 `crash_monitor_prepare_thread()`；
- 再进入原始 worker routine。

这样设计的好处：

- 不需要每个线程入口重复手写 altstack 初始化；
- 接入和审计更统一；
- 新增 C/eBPF worker 时，只要继续复用现有 monitored helper，即可自动纳入 crash monitor 保护范围。

需要注意的是：如果未来新增线程绕过了 monitored helper，那么它即使进程里安装了 fatal handler，也仍可能因为没有 altstack 而抓不到可靠快照。

---

## 12. 当前限制与权衡

### 12.1 模块缓存是有界的

`modules[]` 受 `CRASH_SNAPSHOT_MAX_MODULES` 上限限制。当前设计选择固定上限，是为了保持 ABI 固定大小和 handler 的实现简单性。

影响是：

- 极端情况下，模块数量超过上限时只能保留前 N 个；
- 未进入缓存的模块对应 frame 可能只能退回 raw PC。

### 12.2 `dlopen/dlclose` 动态变化可能导致缓存陈旧

模块缓存是在正常上下文里预构建的。如果进程在之后又发生了大量 `dlopen/dlclose` 变化，那么：

- 某些 frame 可能无法精确匹配到 record 中缓存的模块；
- Stage-2 会对这些帧退回 raw fallback；
- 这是当前设计接受的 trade-off。

### 12.3 依赖 frame pointer

当前回溯主要依赖 frame-pointer walk，因此：

- 对 `-fomit-frame-pointer` 不友好；
- 对高度优化、无标准 frame 链的代码路径，回溯深度可能受限；
- 顶层寄存器信息仍然可信，但 older frames 的完整性不是绝对保证。

### 12.4 不保证一定能拿到 `file:line`

即使 symbolization 已实现，以下情况仍会导致只有 symbol 或 raw 地址：

- 二进制被 strip；
- 系统未安装 debuginfo；
- DWARF sections 不完整；
- 目标地址无法映射到任何行表项；
- candidate debuginfo 与 build-id 不匹配。

### 12.5 crash monitor 不是容错机制

它不能保证：

- 抓到所有崩溃；
- 崩溃后还能继续运行；
- 在极端内存损坏场景下始终可靠落盘。

它的定位始终是：

- **尽力保存证据**；
- **在下一次启动时恢复并解释这些证据**。

---

## 13. 运维与使用注意事项

### 13.1 `.crash` 是结构化二进制文件

不能把 `.crash` 当普通文本日志直接阅读。它保存的是 `struct crash_snapshot_record` 序列，供 Stage-2 消费。

### 13.2 默认会在消费后清空

Stage-2 消费完成后会调用 `ftruncate()` 清空快照文件。因此如果需要长期保留原始崩溃样本，应在 agent 启动前先复制。

### 13.3 容器里要保证路径可写

如果容器环境无法写入 `/var/log/deepflow-agent/`，则即使 handler 触发，快照也无法可靠落盘。

### 13.4 debuginfo 越完整，报告越可读

如果部署环境同时提供：

- 主程序 ELF
- 共享库 ELF
- 对应 build-id 匹配的 debuginfo

那么 Stage-2 能输出最丰富的结果：module、symbol、offset、源码路径、行号、build-id。

---

## 14. 当前能力总结

当前 crash monitor 已具备以下能力：

- fatal signal handler 安装；
- 每线程 altstack 准备；
- 顶层寄存器抓取；
- frame-pointer 有界回溯；
- 固定大小 crash snapshot ABI；
- 固定路径二进制快照写盘；
- `/proc/self/maps` 模块缓存；
- `modules[] / executable_path / module_index / rel_pc` 写入；
- 启动期旧快照消费；
- Stage-2 ELF symbol 解析；
- Stage-2 DWARF `file:line` 解析；
- build-id aware external debuginfo 查找；
- best-effort 多层级日志降级输出。

换句话说，当前实现已经不是“只能打印原始地址的快照消费者”，而是一个完整的：

- **Stage-1 原始崩溃现场采集器**
- **Stage-2 best-effort 崩溃符号化器**

---

## 15. 总结

整个设计的核心思想可以概括为一句话：

> **崩溃当下只保全证据；复杂分析必须延后到正常上下文。**

围绕这一原则，当前实现已经形成完整闭环：

1. 运行前预缓存模块与线程上下文；
2. 崩溃时以 async-signal-safe 风格保存固定大小快照；
3. 下次启动时恢复旧快照；
4. 基于模块、build-id、ELF、DWARF 做 best-effort 符号化；
5. 输出可读崩溃摘要与逐帧报告；
6. 清空已消费快照，继续本次运行。

这保证了：

- 原始崩溃语义不被破坏；
- signal handler 保持足够克制；
- Stage-2 可以不断增强，而不需要把复杂逻辑塞回 fatal path。
