# Crash Monitor 设计说明

## 1. 背景、目标与非目标

DeepFlow Agent 的 eBPF 用户态运行时包含大量直接与内核、ELF、符号表、profiling、线程管理和 native 内存交互的 C 代码路径。这些路径一旦触发 `SIGSEGV`、`SIGABRT`、`SIGBUS`、`SIGILL`、`SIGFPE` 等 fatal signal，进程通常会立即终止；如果没有额外保护，留给排障的往往只有一条粗粒度的系统崩溃信息，无法回答下面这些最关键的问题：

- 到底是哪条线程崩了；
- 崩溃时顶层寄存器分别是多少；
- 调用栈里每一帧属于哪个模块；
- 当前磁盘上的 ELF / debuginfo 能否还原出 `symbol` 与 `file:line`；
- older frames 的参数是否还能从 crash-time 留下的寄存器、frame pointer、栈窗口和 DWARF 表达式中做 best-effort 恢复。

当前 crash monitor 的目标不是“吞掉崩溃”或“让损坏后的进程继续运行”，而是：

1. **保留原始崩溃语义**：进程最终仍按原始 fatal signal 退出。
2. **Stage-1 只做最小证据保全**：fatal signal handler 只抓取有界、固定大小、可安全持久化的原始机器状态。
3. **把复杂分析延后到 Stage-2**：ELF、DWARF、build-id、symbol、`file:line`、per-frame 参数恢复全部放到下一次正常启动时处理。
4. **覆盖 C/eBPF 工作线程**：不仅主线程要准备 altstack，通过 monitored helper 创建的 worker thread 也要统一接入。
5. **对容器部署友好**：崩溃快照固定落盘到 `/var/log/deepflow-agent/deepflow-agent.crash`，便于挂载、收集与离线分析。
6. **在 v4 ABI 上支持更强的恢复能力**：恢复日志里显示完整通用寄存器块，并在条件允许时输出每帧参数信息。

同时它有明确的**非目标**：

- 不尝试在崩溃后继续执行当前进程；
- 不在 fatal signal handler 中做符号化、DWARF 遍历、`/proc` 扫描或复杂日志格式化；
- 不承诺一定恢复出所有帧的源码级参数；
- 不承诺恢复浮点 / SIMD / vector 参数；
- 不承诺在极端内存损坏场景下 100% 落盘成功。

相关源码入口：

- 快照 ABI：`agent/src/ebpf/user/crash_monitor.h:52-296`
- Stage-1 / Stage-2 主实现：`agent/src/ebpf/user/crash_monitor.c:340-1275`
- Stage-2 符号化与参数恢复：`agent/src/ebpf/user/crash_symbolize.c:1810-3145`
- ELF helper：`agent/src/ebpf/user/elf.c:32-646`
- 启动接线：`agent/src/ebpf/user/tracer.c:2196-2199`
- 线程接线：`agent/src/ebpf/user/utils.c:1673-1682`
- 构建接线：`agent/src/ebpf/Makefile:88-89`、`agent/src/ebpf/Makefile:135`
---

## 2. 核心设计原则

### 2.1 严格的两阶段边界

整个机制严格分为两个阶段：

- **Stage-1：fatal signal context**
  - 运行在 `SIGSEGV/SIGABRT/SIGBUS/...` handler 中；
  - 目标是保住原始现场；
  - 只做寄存器抓取、有限栈回溯、模块元数据复制、固定大小二进制快照写盘；
  - 不做 ELF/DWARF 解析，不做 `/proc` 扫描，不做复杂日志格式化。

- **Stage-2：normal process context**
  - 运行在下一次正常启动时；
  - 目标是消费旧快照并输出可读崩溃报告；
  - 允许打开 ELF、读取 split debuginfo、遍历 DWARF、打印 `symbol` 与 `file:line`、做 best-effort 参数恢复；
  - 允许使用常规日志、文件读写、libelf、libdwarf 和其他正常上下文设施。

这两个阶段通过固定大小的 `struct crash_snapshot_record` 作为 ABI 契约连接。

### 2.2 不在 handler 中做不安全工作

fatal signal handler 运行在最不可信的时刻。此时：

- 当前线程的普通栈可能已经损坏；
- 堆状态可能不一致；
- 进程中的锁可能处于未知状态；
- libc / runtime 的内部状态也可能已经不可靠。

因此 Stage-1 明确避免：

- `malloc/free`
- 锁和复杂同步原语
- `stdio` 风格复杂格式化
- `/proc/self/maps` 扫描
- ELF / DWARF 解析
- 常规日志路径
- 任何依赖“进程状态仍然一致”的复杂操作

Stage-1 的理想动作序列只有：

1. 基于 `ucontext_t` 和预缓存元数据构造固定大小 record；
2. 调用 `write()` 追加写盘；
3. 恢复默认信号行为并重新抛出原始 signal。

### 2.3 best-effort，而不是 all-or-nothing

无论 Stage-1 还是 Stage-2，都采用 **best-effort** 策略：

- 某一帧无法识别模块，不影响其他帧；
- 某个模块找不到 debuginfo，不影响其余模块；
- 某一帧没有 `file:line`，也仍然可以输出 symbol 或 raw PC；
- 某个参数 location 可解析但 value 无法读取时，也仍然可以输出 location；
- older frames 即使拿不到真实值，也不会阻断整个 crash report 的输出。

### 2.4 保留原始崩溃语义

crash monitor 是**诊断工具**，不是恢复工具。handler 在写完快照后会恢复默认信号行为并重新抛出原始 signal，确保：

- 进程退出原因仍是原始 fatal signal；
- core dump、容器状态、supervisor 行为仍符合系统预期；
- 不会因为“捕获崩溃”而掩盖未定义行为。

---

## 3. 整体架构与启动时序

### 3.1 启动时序

启动路径中必须保持如下顺序：

1. `crash_monitor_consume_pending_snapshots()`
2. `crash_monitor_init()`

也就是：

- **先消费上一次崩溃留下的旧快照**；
- **再安装本次运行新的 handler、altstack 和快照文件**。

这样设计的原因是：

- Stage-2 需要在完全正常的上下文里运行；
- 它会打开文件、校验记录、遍历 ELF/DWARF、打印格式化日志、清空快照文件；
- 这些动作都不应该放进 fatal signal handler。

### 3.2 启动接线

当前启动接线位于 `agent/src/ebpf/user/tracer.c:2196-2199`，在正常初始化期间先调用：

- `crash_monitor_consume_pending_snapshots()`（`agent/src/ebpf/user/tracer.c:2196`）
- `crash_monitor_init()`（`agent/src/ebpf/user/tracer.c:2199`）

这意味着 `.crash` 文件中的旧记录会在新一轮 agent 正常启动时被恢复成可读日志，而不是在崩溃当下直接做复杂处理。

### 3.3 线程接线

`sigaltstack()` 是**线程级属性**，不是进程级属性。只给主线程安装 altstack 并不能自动覆盖其他工作线程。

当前线程接线位于 `agent/src/ebpf/user/utils.c:1673-1682` 的 monitored thread wrapper：

1. 线程真正进入工作函数前，先把预期线程名传给 `crash_monitor_set_thread_name()`（`agent/src/ebpf/user/utils.c:1681`，实现定义见 `agent/src/ebpf/user/crash_monitor.c:340`）；
2. 然后调用 `crash_monitor_prepare_thread()` 安装该线程自己的 altstack（`agent/src/ebpf/user/utils.c:1682`，实现定义见 `agent/src/ebpf/user/crash_monitor.c:1260`）；
3. 最后才进入真正的 worker routine。

这样可以把 crash monitor 的线程准备逻辑集中到统一入口，避免每个 worker 自己手写一遍。

---

## 4. 快照文件与持久化策略

快照文件固定为：

```c
#define CRASH_SNAPSHOT_FILE "/var/log/deepflow-agent/deepflow-agent.crash"
```

这样做有几个价值：

1. **与运行日志配置解耦**：crash snapshot 不依赖普通 `log_file` 配置；
2. **适合容器持久化**：`/var/log/deepflow-agent/` 很适合被挂载到宿主机或 sidecar；
3. **便于运维收集**：路径稳定，外部系统更容易采集和归档。

需要注意：

- `.crash` 是**结构化二进制快照文件**，不是普通文本日志；
- 默认语义是“启动时消费并清空”；
- 如果需要长期保留原始样本做离线分析，应在 agent 下次启动前复制一份。

---

## 5. Snapshot ABI 设计

快照 ABI 由 `agent/src/ebpf/user/crash_monitor.h:52-296` 定义。当前版本为：

```c
#define CRASH_SNAPSHOT_VERSION 4
```

### 5.1 为什么必须固定大小

固定大小 ABI 的好处是：

- handler 不需要构造变长文本；
- 不需要动态分配内存；
- 只需 `memset()` + bounded field fill + `write()`；
- 读取侧可以按固定步长逐条消费；
- `magic/version/size` 可以做强校验；
- 后续演进时可以受控地维护兼容性。

### 5.2 版本演进

当前 reader 兼容三代 on-disk 记录：

- **v2**：基础崩溃元数据、模块数组、帧数组，但没有线程名、full regs、stack window、frame hints；
- **v3**：在 v2 基础上增加 `thread_name`；
- **v4**：增加完整通用寄存器块、栈窗口、`frame_fp`、`frame_flags` 等字段，用于增强 Stage-2 的日志和参数恢复能力。

兼容策略是：

- 读取侧识别 v2 / v3 / v4；
- 对旧记录在内存中升级为当前 `struct crash_snapshot_record`；
- 新增字段统一 zero-fill；
- 对旧帧补出保守的 `frame_flags`；
- 旧记录不会伪装成“有完整寄存器 / 栈窗口”的新记录，而是通过 `capture_flags` 诚实地降级。

### 5.3 `struct crash_snapshot_module`

每个模块条目保存一个 executable mapping 的关键信息：

- `start` / `end`：崩溃进程中的运行时虚拟地址范围；
- `file_offset`：映射起点对应的文件偏移；
- `build_id` / `build_id_size`：GNU build-id；
- `path`：模块路径。

用途是让 Stage-2 在原进程已经死亡的情况下，仍能把 raw PC 重新绑定回“崩溃时真实观察到的模块布局”。

### 5.4 `struct crash_snapshot_frame`

每一帧现在保存：

- `absolute_pc`：崩溃时的真实运行时地址；
- `rel_pc`：相对 `module.start` 的偏移；
- `frame_fp`：该帧相关的 best-effort frame pointer hint；
- `module_index`：指向 `modules[]` 的索引；
- `frame_flags`：描述该帧来源和性质。

#### `frame_flags` 含义

- `CRASH_SNAPSHOT_FRAME_TOP`
  - 顶层崩溃帧；
- `CRASH_SNAPSHOT_FRAME_FP_WALK`
  - 来自 Stage-1 的 frame-pointer walk；
- `CRASH_SNAPSHOT_FRAME_LR_HINT`
  - AArch64 上额外记录的 link register caller hint；
- `CRASH_SNAPSHOT_FRAME_TRUNCATED`
  - 说明 frame walk 命中固定帧数上限，后续栈帧被截断。

其中 `frame_fp` 的引入很重要：它给 Stage-2 提供了一个与该帧相关的原始 frame pointer 线索，使 `DW_AT_frame_base`、`DW_OP_fbreg`、简单 `CFA+offset` 场景在 older frames 上也有一定恢复基础。

### 5.5 `struct crash_snapshot_record`

顶层 record 保存：

- `magic/version/arch/size`：格式识别与校验；
- `signal/si_code/pid/tid/fault_addr`：崩溃摘要；
- `ip/sp/fp/lr`：顶层控制寄存器快照；
- `args[]`：top frame 的原始 ABI 参数寄存器；
- `executable_path`：可执行文件路径；
- `thread_name`：崩溃线程名；
- `modules_count` + `modules[]`：模块缓存；
- `frames_count` + `frames[]`：栈帧数组；
- `capture_flags`：记录扩展数据是否真的存在；
- `stack_window_start/stack_window_size/stack_window[]`：栈窗口；
- `registers`：完整通用寄存器块。

#### `capture_flags` 含义

- `CRASH_SNAPSHOT_FLAG_FULL_REGS`
  - 说明记录中包含完整 top-frame 通用寄存器块；
- `CRASH_SNAPSHOT_FLAG_STACK_WINDOW`
  - 说明记录中包含有效的栈窗口副本。

### 5.6 完整寄存器块的边界

v4 当前只扩展到**通用寄存器**，不包括 SIMD / FP / vector 寄存器。

- x86_64：`rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp/r8-r15/rip/eflags`
- aarch64：`x0-x30/sp/pc/pstate`

这已经足够支撑：

- 更完整的 recovered register logging；
- top-frame 的寄存器值检查；
- 受限的 DWARF location expression 求值。

但它**不代表**可以恢复：

- SSE/AVX 参数；
- 浮点寄存器参数；
- 任意 older frame 的完整寄存器文件。

### 5.7 `args[]` 的定位

`args[]` 仍然保留，但它的定位非常明确：

- 只是 **top frame 的原始 ABI argument registers**；
- 它是低层原始证据，不等同于源码级参数列表；
- 不保证能恢复 stack-passed、floating-point、optimized-out 或 older-frame 参数。

也就是说，v4 并不是用 full regs 替代 `args[]`，而是：

- `args[]` 继续保留为简洁的 ABI subset；
- `registers` 负责提供更完整的 top-frame 通用寄存器视图；
- `frames[] + frame_fp + stack_window + DWARF` 负责做 per-frame best-effort 参数恢复。

---

## 6. Stage-1：正常上下文预处理

虽然 Stage-1 的核心执行点在 fatal signal handler 中，但为了满足 signal-safety 约束，许多准备工作必须在进程**尚未崩溃**时完成。

### 6.1 打开固定快照文件

`crash_monitor_init()`（`agent/src/ebpf/user/crash_monitor.c:1275`）在正常上下文中打开 `.crash` 文件，并把 fd 长期保留。这样 handler 崩溃当下只需重用该 fd 调用 `write()`。

### 6.2 预缓存模块布局

`crash_cache_modules()`（`agent/src/ebpf/user/crash_monitor.c:376`）会在正常上下文中读取 `/proc/self/maps`，筛选出：

- file-backed
- 可执行
- 有绝对路径

的映射，并缓存：

- 地址范围；
- 文件偏移；
- 模块路径；
- build-id。

这样做的目的：

- handler 不需要再扫描 `/proc/self/maps`；
- Stage-2 不依赖已经不存在的旧进程地址空间；
- 记录里直接携带“崩溃时观察到的真实模块布局”。

### 6.3 缓存 executable path 与线程/进程名称

正常上下文中还会缓存：

- 主程序路径；
- 进程名；
- monitored thread 提前写入的线程逻辑名。

这样 handler 在崩溃时只需做 bounded copy，而不需要去读 `/proc/thread-self/comm` 之类的信息。

### 6.4 为每个线程准备 altstack

`crash_monitor_prepare_thread()`（`agent/src/ebpf/user/crash_monitor.c:1260`）最终调用 altstack 安装逻辑，为当前线程分配并注册独立 signal stack。

这是非常关键的设计点：如果崩溃由普通栈损坏、栈溢出、frame-pointer 链错误等问题引起，那么继续在原普通栈上运行 handler 很可能再次 fault。altstack 能显著提高“至少把快照写出来”的概率。

### 6.5 预缓存线程普通栈边界

altstack 之外，代码还会在正常上下文中记录当前线程的**普通栈边界**。这点非常重要，因为：

- `ucontext_t::uc_stack` 描述的是信号 altstack 状态；
- 但 Stage-1 做 frame-pointer walk 时，需要约束的是被打断线程的**正常工作栈**。

因此后续回溯与 stack window 复制都基于预缓存的普通栈边界进行保守检查。

---

## 7. Stage-1：fatal signal 捕获流程

### 7.1 覆盖的 fatal signals

当前覆盖：

- `SIGSEGV`
- `SIGABRT`
- `SIGBUS`
- `SIGILL`
- `SIGFPE`

安装 handler 时使用的关键标志：

- `SA_SIGINFO`：让 handler 拿到 `siginfo_t` 与 `ucontext_t`；
- `SA_ONSTACK`：强制 handler 在 altstack 上运行；
- `SA_RESETHAND`：第一次触发后恢复默认行为，便于重新抛出原始 signal。

### 7.2 构造 record 头部

fatal signal 到来后，handler 会在栈上构造一个固定大小的 `struct crash_snapshot_record`，填入：

- `magic`
- `version`
- `size`
- `signal`
- `si_code`
- `pid`
- `tid`
- `fault_addr`

然后把预缓存的模块、可执行路径和线程名复制进 record。

### 7.3 从 `ucontext_t` 采集寄存器

#### x86_64

从 `ucontext_t` 提取：

- `RIP -> ip`
- `RSP -> sp`
- `RBP -> fp`
- `RDI/RSI/RDX/RCX/R8/R9 -> args[]`

并进一步写入完整寄存器块：

- `rax/rbx/rcx/rdx/rsi/rdi/rbp/rsp/r8-r15/rip/eflags`

同时设置 `CRASH_SNAPSHOT_FLAG_FULL_REGS`。

#### aarch64

从 `ucontext_t` 提取：

- `pc -> ip`
- `sp -> sp`
- `x29 -> fp`
- `x30 -> lr`
- `x0-x7 -> args[]`

并进一步写入完整寄存器块：

- `x0-x30/sp/pc/pstate`

同时设置 `CRASH_SNAPSHOT_FLAG_FULL_REGS`。

### 7.4 栈窗口采集

v4 在 Stage-1 里还会抓取一个固定大小的栈窗口：

- 上限由 `CRASH_SNAPSHOT_STACK_WINDOW_SIZE` 控制，当前为 `2048` 字节；
- 起点优先取有效的 `sp`；
- 如果 `fp` 也有效且比 `sp` 更低，则起点下探到 `fp`；
- 复制范围被严格限制在已缓存的线程普通栈边界之内；
- 最终设置：
  - `stack_window_start`
  - `stack_window_size`
  - `CRASH_SNAPSHOT_FLAG_STACK_WINDOW`

这不是为了“保存整个线程栈”，而是为了给 Stage-2 留下一小段**可验证、可界定、可安全读取**的 crash-time 栈证据，使某些 stack-backed 参数有机会恢复出值。

### 7.5 帧采集与 `frame_fp` / `frame_flags`

Stage-1 的栈回溯采用 **frame-pointer walk**，而不是 `backtrace()` 或完整 unwind VM。其目标不是最强回溯，而是在 signal context 下以最小逻辑获取可用 backtrace 候选。

当前策略：

1. 先把顶层崩溃帧作为 `CRASH_SNAPSHOT_FRAME_TOP` 记录进去；
2. AArch64 上再把 `lr` 作为 `CRASH_SNAPSHOT_FRAME_LR_HINT` 额外记录一帧 caller hint；
3. 然后沿 frame pointer 做有界回溯；
4. 每一帧记录：
   - `absolute_pc`
   - `frame_fp`
   - `frame_flags`
5. 命中最大帧数后，对最后一帧打上 `CRASH_SNAPSHOT_FRAME_TRUNCATED`。

### 7.6 为什么要记录 `frame_fp`

older frames 不再有完整寄存器快照；对它们来说，能可靠留下来的上下文非常有限。`frame_fp` 的价值在于：

- 给 Stage-2 一个与该帧对应的原始 frame pointer hint；
- 使 `DW_AT_frame_base` 缺失时，仍可退回 frame pointer 作为简化 frame base；
- 使简单的 `DW_OP_fbreg` / `CFA+offset` 参数恢复成为可能。

### 7.7 模块注释：`module_index + rel_pc`

在所有帧采集完成后，Stage-1 会再次遍历 `frames[]`，把每帧的 `absolute_pc` 映射到预缓存的 `modules[]`：

- `module_index`
- `rel_pc`

这一步非常关键，因为：

- 单靠 `absolute_pc`，Stage-2 无法在新进程中直接复原旧进程的 ASLR 布局；
- 有了 `module_index + rel_pc`，Stage-2 才能稳定地重建 file-relative / ELF-relative PC；
- 即使后续某步失败，`absolute_pc` 仍可作为 fallback 输出。

### 7.8 写盘与重新抛出 signal

最终 handler 使用 `write()` 把整个固定大小 record 追加到 `.crash` 文件，然后：

1. 恢复该 signal 的默认行为；
2. 重新向自身发送同一个 signal；
3. 保持原始崩溃退出语义。

---

## 8. Stage-2：消费旧快照

### 8.1 读取流程

启动时 `crash_monitor_consume_pending_snapshots()`（`agent/src/ebpf/user/crash_monitor.c:1212`）会：

1. 以读写方式打开 `.crash` 文件；
2. 循环读取每条 record header；
3. 根据 `magic/version/size` 判断是 v2 / v3 / v4 哪种记录；
4. 对旧记录做内存内升级；
5. 调用 `crash_symbolize_record()`（`agent/src/ebpf/user/crash_symbolize.c:3145`）输出可读报告；
6. 全部完成后 `ftruncate(fd, 0)` 清空文件。

### 8.2 兼容读取与升级

- 对 **v4**：直接读入当前结构；
- 对 **v2**：升级时补零线程名、full regs、stack window，并为帧合成保守的 `frame_flags`；
- 对 **v3**：保留线程名，其余新字段补零，并同样合成保守帧标记。

因此旧快照仍可继续消费，但能力会自动降级为：

- 只有 partial register view；
- 没有 stack window-backed 参数值恢复；
- older frames 的参数更多只能显示 `<unavailable>` 或根本没有 value。

### 8.3 非法记录与截断文件的处理

这里需要区分几种情况：

- **magic 不匹配 / 版本尺寸不认识**
  - 视为非法 record；
  - 打 warning；
  - 跳过继续读下一条。

- **读取某条合法格式记录时发生短读 / I/O 错误**
  - 当前消费流程会返回失败；
  - 不会把它当成“正常可跳过”的记录继续向后消费。

这意味着：文档里的“截断尾部只 warning 然后继续”并不准确；当前实现对真正的短读/损坏是更保守的处理。

### 8.4 清空策略

只有整个消费流程正常跑完后，才会对 `.crash` 文件执行 `ftruncate(fd, 0)`。如果消费过程中返回错误，则不会伪装成“已经完整消费成功”。

---

## 9. Stage-2：符号化恢复链路

### 9.1 总体顺序

对每一帧，Stage-2 大致按以下顺序恢复信息：

1. 根据 `frame.module_index` 找到模块；
2. 计算 `file_offset_pc = module.file_offset + frame.rel_pc`；
3. 打开模块 ELF；
4. 用 `elf_file_offset_to_vaddr()`（`agent/src/ebpf/user/elf.c:618`）把 file-relative PC 转回 ELF virtual address；
5. 优先寻找 external debuginfo；
6. 用 debuginfo 或模块本体做 symbol / `file:line` / params 恢复；
7. 输出该帧最丰富的日志；
8. 如果某步失败，则退回较低层级表示。

### 9.2 为什么要先转回 ELF vaddr

DWARF location list、line table、subprogram range 等大多工作在 ELF / DWARF 的地址空间，而不是进程运行时的 ASLR 地址空间。

因此 Stage-2 必须先把：

- `module.file_offset`
- `frame.rel_pc`

转换成稳定的 `elf_vaddr`，后续的：

- `elf_symbolize_pc()`（`agent/src/ebpf/user/elf.c:646`）
- `dwarf_lowpc()` / `dwarf_highpc_b()`
- location list range match

才能对齐到同一地址空间。

### 9.3 external debuginfo 查找顺序

优先顺序是：

1. `/usr/lib/debug/.build-id/xx/yyyy....debug`
2. `/usr/lib/debug<module>.debug`

其中第一优先级会先基于 snapshot 里持久化的 build-id 构造路径，再验证 candidate debug image 的 build-id 是否匹配；第二优先级则是常见的 path-based fallback。

这样可以避免仅凭 pathname 误匹配到错误版本的 debuginfo。

### 9.4 ELF symbol 与 DWARF line 的分工

- **ELF symbol**
  - 成本较低；
  - 即使没有完整 DWARF，很多时候也能拿到函数名；
  - 适合做第一层命名恢复。

- **DWARF line**
  - 用于恢复源码路径与行号；
  - 在可用时比单纯 symbol 更强；
  - 也可能补上更准确的 subprogram 名称。

Stage-2 会尽量同时收集 symbol 和 `file:line`，并根据恢复结果做分层降级输出。

### 9.5 `DW_TAG_subprogram` 覆盖匹配不只看 `low_pc/high_pc`

这是 older-frame 参数恢复能否真正落到正确函数上的关键点。

很多编译器、LTO、函数克隆、冷/热路径拆分或较新的 DWARF 生成器，并不会把函数范围编码成单一的：

- `DW_AT_low_pc + DW_AT_high_pc`

而是会使用：

- `DW_AT_ranges + .debug_ranges`（经典 range list）
- `DW_AT_ranges + .debug_rnglists`（DWARF5 rnglists）

如果 Stage-2 只检查 `low_pc/high_pc`，就会出现一种很迷惑的现象：

- ELF symbol 还能命中；
- 某些 line table 也许还能命中；
- 但 formal parameter 恢复找不到正确的 `DW_TAG_subprogram`；
- 最终 older frames 看起来像“没有 params”或一直 `<unavailable>`。

当前实现的覆盖匹配策略是：

1. **优先检查 `low_pc/high_pc`**；
2. 如果该 DIE 没有可用的 `low/high` 覆盖，再检查 `DW_AT_ranges`；
3. **只有当该 DIE 完全没有显式 PC coverage 信息时**，才退回到名字匹配。

这个约束非常重要：

- 如果一个 DIE 明明声明了自己的地址覆盖范围，但目标 PC 不在其中，Stage-2 不会再因为名字相似就把它错认成目标函数；
- 只有“这个 DIE 根本没给可比对的 PC coverage”时，名字回退才是合理的保底策略。

### 9.6 对 `DW_AT_ranges` 的两类支持

#### 9.6.1 经典 `.debug_ranges`

对经典 range list，当前实现会：

- 通过 `dwarf_get_ranges_b()` 读取条目；
- 处理：
  - `DW_RANGES_ADDRESS_SELECTION`
  - `DW_RANGES_ENTRY`
  - `DW_RANGES_END`
- 优先使用 subprogram 自己的 `low_pc` 作为 base；
- 若 subprogram 没有 `low_pc`，则退回使用当前 CU 的 `low_pc` 作为 `cu_base`；
- 最终把 range 条目转换到和 `elf_vaddr` 同一语义的地址空间里比较。

这里的 `cu_base` 很关键：经典 range list 的很多条目是“相对 base 的 offset pair”，如果没有一个可靠 base，older-frame 子程序匹配就容易全部落空。

#### 9.6.2 DWARF5 `.debug_rnglists`

对 DWARF5 rnglists，当前实现会：

- 通过 `dwarf_rnglists_get_rle_head()` 拿到 rnglist head；
- 用 `dwarf_get_rnglists_entry_fields_a()` 遍历条目；
- 对可比较的 range entry 使用 libdwarf 已经 cook 好的地址（`cooked1/cooked2`）；
- 若 `debug_addr_unavailable` 置位，则跳过该条目；
- 处理 `DW_RLE_offset_pair`、`DW_RLE_startx_endx`、`DW_RLE_startx_length`、`DW_RLE_start_end`、`DW_RLE_start_length` 等常见形式。

这样可以覆盖一批新工具链默认生成的 `DW_AT_ranges` 形式，而不再局限于老式 `low_pc/high_pc`。

### 9.7 名字回退匹配不是简单字符串比较

当且仅当某个 `DW_TAG_subprogram` 没有可比对的 PC coverage 时，Stage-2 才会退回到名字匹配。这个回退过程本身也做了几层增强：

- 参数名/函数名会递归跟随：
  - `DW_AT_name`
  - `DW_AT_linkage_name`
  - `DW_AT_MIPS_linkage_name`
  - `DW_AT_abstract_origin`
  - `DW_AT_specification`
- 名字比较前会做归一化，去掉常见编译器后缀，例如：
  - `.isra`
  - `.constprop`
  - `.part`
  - `.cold`
  - `.clone`
  - `.llvm.`
- 还会剥离 ELF 符号常见的版本后缀，如 `@GLIBC_...` / `@@GLIBC_...`。

因此，名字回退的目标不是“宽松乱猜”，而是在没有 PC coverage 信息时，尽量把 DWARF DIE 与 ELF symbol 对齐到同一个逻辑函数名。

### 9.8 同一套 range-aware 匹配同时服务 `params` 与 `file:line`

当前 range-aware 子程序匹配并不只用于 formal parameter 恢复，也用于补强 Stage-2 对 subprogram 名称的判断。

也就是说，`DW_AT_ranges` / rnglists 的支持会同时改善：

- `Recovered crash frame[N] params:`
- 某些 frame 的 subprogram 识别
- 与 line table 相配合时的函数名质量

这也是为什么 older-frame 参数恢复的问题，最终不能只盯着 `DW_AT_location`，还必须先把“目标 subprogram 是否找对”这一步补齐。

---

## 10. Stage-2：完整寄存器与 top-frame args 日志

### 10.1 crash summary

每条恢复出的 crash report 都会先打印 summary，包含：

- `task`
- `signal`
- `code`
- `pid`
- `tid`
- `executable`
- `executable_md5`
- `ip`
- `fault_addr`
- `frames`

其中：

- `task` 优先来自 snapshot 的 `thread_name`；
- `executable_md5` 是 Stage-2 对当前磁盘上 `executable_path` 指向文件做的 best-effort 摘要，用于帮助判断“当前恢复环境里的镜像是不是同一个文件”。

### 10.2 full register logging 与 partial register logging

summary 之后紧接着是寄存器输出：

- **v4 且 `FULL_REGS` 置位**
  - 输出完整 top-frame 通用寄存器块；
- **升级后的 v2/v3 旧记录**
  - 输出 `Recovered crash registers (partial): ...`；
  - 只打印旧 ABI 真正持久化过的字段，避免给人“完整寄存器都在”的错觉。

这点非常重要：**Stage-2 不会伪造旧 snapshot 从未保存过的寄存器。**

### 10.3 `Recovered crash args:` 的定位

在寄存器块之后，Stage-2 还会输出一条：

- x86_64：`rdi/rsi/rdx/rcx/r8/r9`
- aarch64：`x0-x7`

这条日志只是 top-frame ABI 参数寄存器视图，方便快速查看崩溃入口的低层调用约定现场。它不是参数恢复系统的最终结果，也不覆盖 older frames。

---

## 11. Stage-2：per-frame 参数恢复

这是 v4 相比早期设计最重要的增强点之一。

### 11.1 为什么需要 v4 才能把这件事做得更有价值

Stage-2 发生在“下次启动”，旧进程已经不存在，因此它**不能**再访问：

- 旧线程 live registers；
- 旧线程完整栈；
- `/proc/<oldpid>/mem`；
- 旧地址空间中的任意内存。

因此 older frames 参数恢复只能依赖 Stage-1 已经保存下来的原始证据。v4 新增的关键证据包括：

- top-frame 完整通用寄存器块；
- `frame_fp`；
- 栈窗口；
- `frame_flags`；
- 稳定的 `module_index + rel_pc` / `elf_vaddr` 映射。

### 11.2 当前参数恢复的整体策略

对每一帧，Stage-2 会：

1. 找到包含该 `elf_vaddr` 的 `DW_TAG_subprogram`；
2. 枚举其 `DW_TAG_formal_parameter`；
3. 尝试读取参数名；
4. 尝试求值 `DW_AT_location`；
5. 按 best-effort 原则输出 value、location 或 `<unavailable>`。

### 11.3 参数名如何恢复

参数名优先来自 `DW_AT_name`。如果当前 DIE 没有直接名字，会继续跟随：

- `DW_AT_abstract_origin`
- `DW_AT_specification`

去补齐名字。若仍不可得，则退回为：

- `arg0`
- `arg1`
- ...

### 11.4 为什么 location list 匹配要用 `dwarf_pc`

当前实现不会直接用 `frame.absolute_pc` 去匹配 location list，而是优先使用已经重建好的 `elf_vaddr`。原因是：

- `absolute_pc` 是进程运行时地址，受 ASLR 影响；
- DWARF range / location list 工作在 ELF / DWARF 地址空间；
- 只有使用 `elf_vaddr`，location list 才能与 line table、subprogram range 保持一致。

这保证了参数恢复链路与符号化链路使用同一套地址语义。

### 11.5 当前支持的 DWARF location expression 子集

当前实现支持一组**受限但高价值**的 DWARF op：

- `DW_OP_regN`
- `DW_OP_bregN`
- `DW_OP_fbreg`
- `DW_OP_call_frame_cfa`
- `DW_OP_plus_uconst`
- `DW_OP_consts`
- `DW_OP_constu`
- `DW_OP_stack_value`

这意味着它适合处理：

- 参数直接在寄存器中的情况；
- 参数在“寄存器 + 偏移”地址中的情况；
- 参数在 frame base / CFA 附近栈槽里的情况；
- 简单常量表达式。

### 11.6 当前**不支持**或不会完整处理的表达式

第一版不会承诺处理完整 DWARF VM，尤其包括：

- `DW_OP_piece` / `DW_OP_bit_piece`
- `DW_OP_entry_value`
- TLS 相关复杂表达式
- implicit pointer / complex call ops
- 浮点 / vector 参数位置
- 任何依赖旧进程未保存寄存器或未保存内存区域的复杂表达式

这些场景会自动降级为 location-only 或 `<unavailable>`，而不会伪造数值。

### 11.7 `frame_base` 与 `DW_AT_location` 的语义区别

这里有一个非常关键但容易误解的点：

- `DW_AT_frame_base`
  - 当前实现按“地址语义”求值；
  - **不会**把它当成“应该立刻解引用的内存地址”；
  - 这是后续 `DW_OP_fbreg` 的基底。

- `DW_AT_location`
  - 当前实现按“参数位置表达式”求值；
  - 如果最终结果是地址，并且该地址落在已捕获的 `stack_window` 内，则会尝试把该地址对应的 8 字节内容读出来作为 value；
  - 如果地址不在 `stack_window` 内，则保留 location，但不伪造 value。

简单说：

- frame base / CFA 负责描述“去哪找”；
- stack window 负责在“证据真的存在”时提供“读出来的值”。

### 11.8 simple CFA 的来源

当前实现没有引入完整 CFI unwind 解释器，而是使用一个保守的简化策略：

- 当 `frame_fp` 可用时，x86_64 / aarch64 都把 `CFA` 近似为 `frame_fp + 16`。

这和标准 ABI 下常见的“保存的 FP + 返回地址”布局一致，足以覆盖一部分简单 stack-slot 参数恢复场景，但它不是一个通用 unwind VM。

### 11.9 older frames 为什么仍然只能是 best-effort

只有 top frame 才有完整通用寄存器块。older frames 没有完整 caller-saved/callee-saved 寄存器快照，因此它们的参数恢复主要依赖：

- `frame_fp`
- simple CFA
- `stack_window`
- DWARF location expression

这意味着：

- 对 `fbreg` / `cfa+offset` 这类参数，older frames 可能恢复出值；
- 对“纯寄存器参数”且该寄存器没有 crash-time 证据的 older frame，通常只能得到 location 或 `<unavailable>`；
- 这是设计上的能力边界，不是 Stage-2 的 bug。

### 11.10 top-frame ABI fallback

如果某个 formal parameter 的 DWARF 恢复失败，但它属于 top frame，Stage-2 还会尝试退回到 `args[]`：

- x86_64：`rdi/rsi/rdx/rcx/r8/r9`
- aarch64：`x0-x7`

这提供了一个非常实用的兜底：即使 debuginfo 不完整，top frame 的前若干整数/指针参数仍可能给出原始值。

### 11.11 参数日志的输出形态

参数不会塞进原有 frame line，而是单独打印一行：

```text
Recovered crash frame[2] params: fd=0x3 @rdi buf=<unavailable> @rbp-0x20 len=0x400 @rbp+0x10
```

目前可能出现的几种形式：

- `name=0x1234 @rdi`
  - 有值，也知道它来自哪个寄存器或位置；
- `name=0x1234 @rbp+0x10`
  - 有值，并且值是从栈槽恢复出来的；
- `name=<unavailable> @x29-0x18`
  - location 可知，但 value 无法从现有证据读取；
- `name=<unavailable>`
  - 名字能枚举出来，但没有足够证据恢复位置和值。

### 11.12 如何解读 older-frame 参数日志

older-frame 参数日志最容易被误解的地方，是“为什么已经出现 `params:` 了，但很多值还是 `<unavailable>`”。这里需要把几类结果区分开看：

#### 11.12.1 `params:` 一行出现，本身就说明子程序匹配已经成功了

如果日志里出现：

```text
Recovered crash frame[1] params: req=<unavailable> rem=<unavailable>
```

这至少说明以下步骤已经成功：

1. 该 frame 已成功映射到模块；
2. 已成功重建 `elf_vaddr`；
3. 已找到与该地址匹配的 `DW_TAG_subprogram`；
4. 已枚举出其 `DW_TAG_formal_parameter`；
5. 已恢复出参数名或参数序号。

因此，`<unavailable>` 并不等同于“older-frame 恢复没工作”。很多时候它恰恰说明：

- older-frame 的 **函数匹配已经对了**；
- 只是当前保存下来的 crash-time 证据不足以把值也恢复出来。

#### 11.12.2 `params:` 完全没有，通常要优先排查三类问题

如果一帧连 `Recovered crash frame[N] params:` 都没有，通常优先看：

1. **该二进制/库是否真的有 DWARF debuginfo**；
2. **目标地址是否被 line/subprogram/ranges 覆盖**；
3. **该帧是否只是有 symbol，但没有 formal parameter 信息**。

当前实现里，“完全没有 params 行”和“有 params 行但值不可用”是两个不同层级的问题，排查方向也不同。

#### 11.12.3 older frames 的 `<unavailable>` 很多时候是设计边界，不是 bug

older frames 没有完整寄存器文件，因此像下面这些参数更容易拿不到值：

- 纯寄存器参数，但对应寄存器没有 crash-time 证据；
- 参数位置落在 stack window 之外；
- 参数表达式依赖未实现的 DWARF op；
- 参数已经被优化掉；
- 参数原本就在浮点 / vector 寄存器里。

这些场景里，当前实现更倾向于：

- 输出 location；
- 或输出 `<unavailable>`；
- 而不是猜一个看似合理但未经证据支持的数值。

### 11.13 一次真实验证里能说明什么、不能说明什么

在一次实际的 `socket_tracer` 崩溃恢复验证中，可以看到类似：

```text
Recovered crash frame[1] params: req=<unavailable> rem=<unavailable>
Recovered crash frame[2] params: useconds=<unavailable>
Recovered crash frame[5] params: arg=<unavailable>
Recovered crash frame[6] params: arg0=<unavailable> arg1=<unavailable> arg2=<unavailable> arg3=<unavailable>
```

这类输出说明：

- older-frame 的 parameter enumeration 已经在工作；
- `DW_AT_ranges` / rnglists 匹配已经让 older frames 能正确落到对应 subprogram；
- 但 value recovery 仍严格受限于 crash-time 证据、DWARF 位置表达式复杂度以及 stack window 覆盖范围。

换句话说，这类日志更接近“恢复链路已经打通，但证据不足以恢复值”，而不是“Stage-2 完全没命中 older frame”。

---

## 12. Stage-2：日志格式与降级策略

### 12.1 报告边界

每条恢复出的 crash report 都会用固定分隔线括起来，便于在普通 agent 日志中快速定位整段恢复报告。

### 12.2 日志大致顺序

1. 分隔线
2. `Recovered crash snapshot: ...`
3. `Recovered crash registers: ...` 或 `Recovered crash registers (partial): ...`
4. `Recovered crash args: ...`
5. 每一帧的 `Recovered crash frame[N]: ...`
6. 如有参数，再打印 `Recovered crash frame[N] params: ...`
7. 分隔线

### 12.3 单帧日志的降级层级

当前每帧日志大致按以下优先级降级：

1. `module + rel_pc + symbol + file:line + build_id`
2. `module + rel_pc + symbol + file:line`
3. `module + rel_pc + file:line + build_id`
4. `module + rel_pc + file:line`
5. `module + rel_pc + symbol + build_id`
6. `module + rel_pc + symbol`
7. `raw pc + module + rel_pc + build_id`
8. `raw pc + module + rel_pc`
9. `raw pc`

参数日志本身也遵循 best-effort：

- 有值就打印值；
- 只有位置就打印位置；
- 都没有就打印 `<unavailable>`；
- 某一帧参数失败，不影响其他帧与整条记录。

### 12.4 当前日志示意

```text
=========================================================
Recovered crash snapshot: task=deepflow-agent signal=11 code=1 pid=123 tid=456 executable=/usr/bin/deepflow-agent executable_md5=0123456789abcdef0123456789abcdef ip=0x7f... fault_addr=0x0 frames=6
Recovered crash registers: rip=0x7f... rsp=0x7ffd... rbp=0x7ffd... eflags=0x10246
Recovered crash registers: rax=0x0 rbx=0x7f... rcx=0x2a rdx=0x0 rsi=0x7f... rdi=0x1
Recovered crash registers: r8=0x7f... r9=0x0 r10=0x... r11=0x... r12=0x... r13=0x... r14=0x... r15=0x...
Recovered crash args: rdi=0x1 rsi=0x7f1234567000 rdx=0x0 rcx=0x2a r8=0x7f1234500000 r9=0x0
Recovered crash frame[0]: pc=0x7f... module=/usr/bin/deepflow-agent rel=0x1234 symbol=foo+0x18 file=/root/project/foo.c:87 build_id=abcd...
Recovered crash frame[0] params: req=0x7f1234567000 @rsi timeout=0x2a @rcx
Recovered crash frame[2]: pc=0x7f... module=/lib64/libc.so.6 rel=0x2a1f0 symbol=malloc+0x30
Recovered crash frame[2] params: bytes=<unavailable> @rbp+0x10
=========================================================
```

需要注意三点：

1. `executable_md5` 是 Stage-2 针对**当前磁盘文件**做的摘要，不是崩溃当下持久化进 snapshot 的字段；
2. `Recovered crash args:` 是 top-frame 原始 ABI 参数寄存器视图，不等同于 formal parameters 恢复结果；
3. `Recovered crash frame[N] params:` 是当前 per-frame 参数恢复的最终用户可见输出，它是建立在 DWARF + capture evidence 上的 best-effort 结果。

---

## 13. 当前限制与权衡

### 13.1 模块缓存是有界的

`modules[]` 受 `CRASH_SNAPSHOT_MAX_MODULES` 限制。超过上限时只能保留前 N 个模块，未入缓存的帧可能退回 raw PC。

### 13.2 `dlopen/dlclose` 可能让缓存陈旧

模块缓存是在正常上下文中预构建的。如果之后进程又发生大量 `dlopen/dlclose` 动态变化，那么：

- 某些 frame 可能无法精确匹配到缓存模块；
- Stage-2 会对这些帧退回 raw fallback；
- 这是固定大小 ABI 与 signal-safety 的 trade-off。

### 13.3 当前回溯依赖 frame pointer

当前 Stage-1 主要依赖 frame-pointer walk，因此：

- 对 `-fomit-frame-pointer` 不友好；
- 对高度优化、无标准 frame 链的路径，回溯深度可能受限；
- older frames 的参数恢复也会随之受影响。

### 13.4 older frames 没有完整寄存器文件

只有 top frame 保存了完整通用寄存器。older frames 的参数恢复更多依赖：

- `frame_fp`
- simple CFA
- 栈窗口
- DWARF location

因此 older frames 的“纯寄存器参数”无法像 top frame 那样普遍恢复。

### 13.5 栈窗口是有界的

当前栈窗口固定为 2048 字节，只覆盖 `sp/fp` 附近的一小段正常栈证据。超出窗口的地址不会被读取，因此：

- 某些 stack-backed 参数只能得到 location，拿不到 value；
- 这是一种有意识的安全与复杂度控制。

### 13.6 不是完整 DWARF VM

当前并未实现完整的 DWARF expression / unwind 解释器。复杂表达式、piecewise 参数、entry value、TLS 等场景会降级处理。

### 13.7 不保证一定拿到 `file:line`

即使 symbolization 已实现，以下情况仍会导致只有 symbol 或 raw 地址：

- 二进制被 strip；
- 系统未安装 debuginfo；
- DWARF sections 不完整；
- 行表无法覆盖目标地址；
- candidate debuginfo 与 build-id 不匹配。

### 13.8 不保证所有崩溃都能捕获

它不能保证：

- 抓到所有崩溃；
- 崩溃后还能继续运行；
- 在极端内存损坏场景下始终可靠落盘。

它的定位始终是：

- **尽力保存证据**；
- **在下一次启动时恢复并解释这些证据**。

---

## 14. 运维与使用注意事项

### 14.1 `.crash` 是二进制快照文件

不能把 `.crash` 当普通文本日志直接阅读。它保存的是 `struct crash_snapshot_record` 序列，供 Stage-2 消费。

### 14.2 默认会在消费后清空

Stage-2 消费完成后会 `ftruncate()` 清空快照文件。因此如果需要保留原始崩溃样本，应在 agent 启动前先复制。

### 14.3 容器里要保证路径可写

如果容器环境无法写入 `/var/log/deepflow-agent/`，则即使 handler 触发，也无法可靠落盘。

### 14.4 debuginfo 越完整，报告越可读

如果部署环境同时提供：

- 主程序 ELF
- 共享库 ELF
- 对应 build-id 匹配的 debuginfo

那么 Stage-2 才能输出最丰富的结果：

- 完整模块路径
- build-id
- symbol
- `file:line`
- per-frame 参数位置与部分参数值

### 14.5 尽量保留 frame pointer

当前构建链路保留了 `-fno-omit-frame-pointer`（`agent/src/ebpf/Makefile:135`）。如果未来某些相关组件关闭 frame pointer，回溯质量与 per-frame 参数恢复质量都会下降。

### 14.6 Rust sample / release 构建时的 debuginfo 要求

对 Rust sample 来说，是否能恢复出应用自身帧的 `file:line` 与 formal parameters，往往首先取决于 release 产物里是否真的保留了 DWARF。

一个很常见、也很容易误判的现象是：

- `file` 命令显示二进制 **not stripped**；
- `ELF symbol` 仍然能给出函数名；
- 但 Stage-2 对应用自身帧仍然没有 `file:line`，也没有 `params:`。

这里的关键点是：

- **not stripped ≠ 有 DWARF debuginfo**
- 一个二进制即使保留了 `.symtab` / `.strtab`，也依然可能完全没有：
  - `.debug_info`
  - `.debug_abbrev`
  - `.debug_line`
  - `.debug_str`
  - `.debug_ranges` / `.debug_rnglists`

在这种情况下，Stage-2 仍可能拿到：

- `symbol`
- `module`
- `rel_pc`

但无法拿到：

- `file:line`
- `DW_TAG_formal_parameter`
- `DW_AT_location`
- per-frame `params:`

#### 推荐的 Rust release 配置

当前 sample 推荐使用：

```toml
[profile.release]
panic = 'abort'
debug = 2
split-debuginfo = "off"
```

其含义分别是：

- `panic = 'abort'`
  - 更接近 crash monitor 要观测的“原生崩溃/终止”语义；
- `debug = 2`
  - 在 release 中保留完整 DWARF；
- `split-debuginfo = "off"`
  - 让 DWARF 直接保留在主二进制里，便于当前 Stage-2 直接从目标 ELF 读取。

当前 sample 已按这组方式配置：

- `agent/src/ebpf/samples/rust/socket-tracer/Cargo.toml:21-24`
- `agent/src/ebpf/samples/rust/profiler/Cargo.toml:21-24`

#### 如何确认 release 产物里真的有 debuginfo

不要只看 `file` 命令。更可靠的是直接检查 section：

```bash
readelf -S samples/rust/socket-tracer/target/release/socket_tracer | grep debug_
readelf -S samples/rust/profiler/target/release/profiler | grep debug_
```

如果能看到至少部分：

- `.debug_info`
- `.debug_abbrev`
- `.debug_line`
- `.debug_str`

那么 Stage-2 对应用自身帧的恢复能力才算真正具备基础。

如果只能看到：

- `.symtab`
- `.strtab`

但完全没有 `.debug_*`，那么通常会出现：

- 应用帧有 `symbol`；
- 但没有 `file:line`；
- 也没有 `Recovered crash frame[N] params:`。

### 14.7 如何排查“有 symbol，但应用自身帧没 params”

推荐按下面顺序看：

1. **先看是否有 `.debug_*` section**
   - 没有的话，先解决构建配置；
2. **再看系统库是否有 debuginfo**
   - 如果 libc 帧能出 `file:line` / `params`，而应用帧不行，往往说明 crash monitor 主链路是通的，问题主要在应用自身 debuginfo；
3. **再看是不是 older-frame 证据不足**
   - 若应用帧已经出现 `params:`，但大量 `<unavailable>`，则通常不是 debuginfo 缺失，而是 older-frame 恢复的正常边界。

这个排查顺序很重要，因为它能把三类问题明确分开：

- **没有 DWARF**
- **DWARF 子程序匹配失败**
- **DWARF 已命中，但值证据不足**

### 14.8 一次典型现象应该如何解释

如果你看到这样的组合：

- libc 帧有 `file:line`，也有 `params:`；
- 应用自身帧只有 `symbol`，没有 `file:line`，也没有 `params:`；
- 二进制 `file` 显示为 `not stripped`；
- 但 `readelf -S` 看不到任何 `.debug_*`；

那么最合理的解释通常是：

- crash monitor 的 Stage-2 主逻辑已经正常工作；
- older-frame range-aware 匹配也已经在系统库帧上生效；
- 应用自身帧缺参数的主要原因是 **release 产物没把 DWARF 带进来**。

这类现象本身不应被解读为“older-frame 参数恢复又坏了”。

### 14.9 基于这次 `profiler` 实际日志的完整案例分析

这次 `samples/rust/profiler/target/release/profiler` 的恢复日志，比前面的 `socket_tracer` 样例更能说明：当 release 产物真的带上 DWARF 之后，当前 Stage-2 已经可以同时覆盖：

- 应用自身的 C 帧；
- 应用自身的 Rust 帧；
- libc 的 older frames；
- 同一条日志里 top-frame 与 older-frame 的不同恢复层级。

可以先抓住下面几个最关键的实际现象：

```text
Recovered crash frame[0]: ... symbol=setup_bpf_tracer+0x3a file=/work/agent/src/ebpf/user/tracer.c:226 ...
Recovered crash frame[0] params: name=0x577e25dc66b2 @r12 load_name=0x7ffd0560c0f0 @rsi bpf_bin_buffer=0x0 @rdx buffer_sz=0x1 @rcx tps=0x577e5dc65f80 @r8 workers_nr=0x1 @r9 ...
Recovered crash frame[1]: ... symbol=running_socket_tracer+0x198 file=/work/agent/src/ebpf/user/socket.c:2568 ...
Recovered crash frame[1] params: handle=<unavailable> @r12 thread_nr=0x1 @rbp+0x10-0xa8d8 perf_pages_cnt=0x40 @rbp+0x10-0xa8e0 queue_size=0x10000 @rbp+0x10-0xa8f4 ...
Recovered crash frame[2]: ... symbol=_ZN8profiler4main17h... file=/work/agent/src/ebpf/samples/rust/profiler/src/main.rs:178 ...
```

#### 14.9.1 这首先说明 release debuginfo 已经真的生效

当前 `profiler` sample 的 release 配置位于 `agent/src/ebpf/samples/rust/profiler/Cargo.toml:21-24`。在这次实际日志里，应用自身模块已经不再只是“有 symbol 但没有源码信息”，而是明确出现了：

- 应用自身帧的 `file:line`；
- Rust 源文件路径；
- older-frame 的参数行；
- libc 与应用模块混合存在时的连续恢复结果。

这和之前 `socket_tracer` 那种“系统库帧能出 `file:line/params`，但应用自身帧只有 symbol”的现象形成了很清晰的对照。也就是说，这次日志本身已经证明：**release debuginfo 缺失的问题在 `profiler` 这个样例上已经被排除。**

#### 14.9.2 `frame[0]` 说明 top-frame 恢复不是简单复读 `args[]`

顶帧符号是 `setup_bpf_tracer`，其函数签名可在 `agent/src/ebpf/user/tracer.c:330-340` 查看。对应日志里恢复出的参数名包括：

- `name`
- `load_name`
- `bpf_bin_buffer`
- `buffer_sz`
- `tps`
- `workers_nr`
- `free_cb`
- `create_cb`
- `handle`
- `profiler_callback_ctx`
- `sample_freq`

这和源码签名是能对上的，但更关键的是：**值的位置并不只是 SysV ABI 入口寄存器。**

例如日志里：

- `name=... @r12`
- `load_name=... @rsi`
- `bpf_bin_buffer=... @rdx`
- `workers_nr=0x1 @r9`

这里最值得注意的是 `name` 出现在 `@r12`，而不是机械地标成 `@rdi`。这说明当前实现不是把 `args[]` 生硬套上参数名，而是已经在 `crash_recover_parameter_value()`（`agent/src/ebpf/user/crash_symbolize.c:1810`）里按 DWARF location 做了“**崩溃点当前 live location**”恢复。因此：

- `Recovered crash args:` 仍然是 top-frame 的原始 ABI 视图；
- `Recovered crash frame[0] params:` 则是更接近源码语义的 DWARF 驱动视图。

这两行日志一起看，才能正确理解 top-frame 参数恢复的价值。

#### 14.9.3 `frame[1]` 是 older-frame 参数值恢复已经落地的直接证据

`frame[1]` 对应 `running_socket_tracer`，其函数签名可在 `agent/src/ebpf/user/socket.c:2508-2514` 查看。更重要的是，这一帧恢复出的几个值和 Rust 调用点 `agent/src/ebpf/samples/rust/profiler/src/main.rs:178-185` 是能直接对上的：

- `thread_nr=0x1`
- `perf_pages_cnt=0x40`
- `queue_size=0x10000`
- `max_trace_entries=0x20000`

这几个值并不是 top frame 的 ABI 参数，而是**older frame 自己的参数值**。而且它们的 location 形态是：

- `@rbp+0x10-0xa8d8`
- `@rbp+0x10-0xa8e0`
- `@rbp+0x10-0xa8f4`
- `@rbp+0x10-0xa8dc`

这正是本次改动最关键的验证点之一：它表明当前 older-frame 恢复已经不只是“能枚举参数名”，而是确实能够把：

- `frame_fp`
- stack window
- DWARF location expression
- older-frame subprogram range 匹配

组合起来，恢复出一部分 **真实的非顶帧参数值**。

#### 14.9.4 为什么 `frame[1]` 里仍然有些参数是 `<unavailable>`

同一帧里也有：

- `handle=<unavailable> @r12`
- `max_socket_entries=<unavailable> @rbx`
- `socket_map_max_reclaim=<unavailable> @rbp+0x10`

这类结果不应理解为“older-frame 恢复失败”，而应理解为：

1. 子程序已经匹配成功；
2. 参数名已经枚举成功；
3. location 至少部分已经恢复成功；
4. 但在当前 crash-time 证据下，值本身无法被可靠取回。

也就是说，`<unavailable>` 在这个上下文里表达的是“**诚实降级**”，不是“**根本没命中**”。这正符合当前设计里 best-effort 的边界。

#### 14.9.5 `frame[2]` 没有 `params:`，不代表这一帧恢复失败

`frame[2]` 落在 `agent/src/ebpf/samples/rust/profiler/src/main.rs:178`，而 `main()` 本身定义在 `agent/src/ebpf/samples/rust/profiler/src/main.rs:157`。这条日志至少说明两件事：

- Rust release 二进制里的 `file:line` 已经可以恢复出来；
- line table 已经把 PC 准确落到了 `running_socket_tracer(...)` 的调用点附近。

同时，`frame[2]` 没有出现 `params:` 并不奇怪，因为 Rust 这里的 `main()` 本身并没有源码级 formal parameters 需要恢复。这个例子很重要，因为它说明：

- “没有 `params:`” 并不总是异常；
- 它有时只是因为该函数本来就没有可枚举的参数，或者该帧对应的是 callsite 语义更强的一段代码位置。

#### 14.9.6 运行时 / 启动帧的混合结果也符合预期

后续日志里还能看到：

- `frame[3]` 的 `f=<unavailable> @rdi`
- `frame[7]` 的 `main/argc/argv`
- `frame[8]` 的 `main/argc/argv/init/fini/rtld_fini/stack_end`

它们共同说明：

- 不是只有顶帧和应用帧能出参数；
- libc startup older frames 也已经可以输出参数名与部分位置；
- 某些运行时包装层、closure、启动桩会天然更容易出现 `<unavailable>`，因为它们经常伴随更重的优化、寄存器重用或更难的 DWARF 表达式。

因此，这类“有的帧能恢复值，有的帧只能恢复位置，有的帧只有 `file:line`”的混合结果，恰恰是当前实现真实而健康的表现，而不是异常现象。

#### 14.9.7 这次实际日志能得出的最终结论

基于这次 `profiler` 实际日志，可以比较明确地得出下面几条结论：

1. `v4` snapshot 的 full-register 持久化已经正常工作；
2. release 带 debuginfo 的 Rust sample 已经能恢复出应用自身帧的 `file:line`；
3. older-frame 参数恢复已经不只是“枚举名字”，而是能恢复出一部分真实值；
4. `frame_fp + stack_window + DWARF` 这条设计路线已经被实际日志验证；
5. 剩余的 `<unavailable>` 主要反映的是证据边界，而不是主链路损坏。

如果要用一句话概括这次案例，最准确的表述应当是：

> **当前实现已经能在真实日志中同时证明“应用帧可符号化”和“older-frame 参数可部分恢复”；剩下没有恢复出的部分，更多是 best-effort 的天然边界，而不是实现根本不可用。**

### 14.10 常见问题（Q&A）

#### Q1：older frame 的参数是怎么恢复的？

**A：**older frame 的参数恢复不是靠“还原完整寄存器现场”，而是靠 **Stage-1 留下的有限证据** 与 **Stage-2 的 DWARF location 求值** 组合完成的。

可以把主链路概括为：

1. **Stage-1 先留证据**
   - 记录每帧的 `absolute_pc`、`frame_fp`、`frame_flags`；
   - 为每帧注释 `module_index + rel_pc`；
   - 持久化 top-frame 的 full regs / `args[]`；
   - 持久化一小段有界 `stack_window`。

2. **Stage-2 先把“这是哪个函数”搞清楚**
   - 通过 `module_index` 找到该帧所属模块；
   - 用 `file_offset_pc = module->file_offset + frame->rel_pc` 重建 file-relative PC；
   - 再把 file-relative PC 转回 ELF / DWARF 需要的 `elf_vaddr`；
   - 用这个 `elf_vaddr` 去匹配 `DW_TAG_subprogram`、行表和参数 DIE。

3. **Stage-2 再枚举 formal parameters 并解释 `DW_AT_location`**
   - 对每个 `DW_TAG_formal_parameter`，读取它在当前 PC 下的 `DW_AT_location`；
   - 在求值前，尽量准备 `frame_base` 和简单 `CFA`；
   - 若表达式落到寄存器、`frame_base + offset` 或 `CFA + offset` 这类当前实现支持的形式，就继续恢复。

4. **最后看能不能把“位置”变成“值”**
   - 如果位置对应 top frame 仍然活着的 ABI 参数寄存器，可直接给值；
   - 如果位置落在 `stack_window` 覆盖范围内，可从快照中的栈副本读取值；
   - 如果只能确定位置但读不到值，就输出 `name=<unavailable> @location`；
   - 如果连位置也无法稳定解释，就只剩 `<unavailable>`。

因此 older frame 的参数恢复本质上是：**先靠 `module_index + rel_pc` 找到正确的 DWARF 子程序，再用 `frame_fp + stack_window + 受限 DWARF 表达式求值` 去 best-effort 恢复参数位置和值。**

**实现对应代码位置：**

- Stage-1 模块缓存与快照复制：`agent/src/ebpf/user/crash_monitor.c:376`、`agent/src/ebpf/user/crash_monitor.c:446`
- Stage-1 为帧补 `module_index + rel_pc`：`agent/src/ebpf/user/crash_monitor.c:467`
- Stage-1 记录帧与 `frame_fp`：`agent/src/ebpf/user/crash_monitor.c:537`、`agent/src/ebpf/user/crash_monitor.c:551`、`agent/src/ebpf/user/crash_monitor.c:765`
- Stage-1 采集 `stack_window` / full regs / `ucontext_t`：`agent/src/ebpf/user/crash_monitor.c:564`、`agent/src/ebpf/user/crash_monitor.c:594`、`agent/src/ebpf/user/crash_monitor.c:825`
- Stage-2 单帧符号化入口：`agent/src/ebpf/user/crash_symbolize.c:2710`
- Stage-2 参数恢复入口：`agent/src/ebpf/user/crash_symbolize.c:2442`
- Stage-2 formal parameter 递归收集：`agent/src/ebpf/user/crash_symbolize.c:1933`
- Stage-2 单参数恢复：`agent/src/ebpf/user/crash_symbolize.c:1810`
- Stage-2 栈窗口读值：`agent/src/ebpf/user/crash_symbolize.c:878`

#### Q2：这个恢复原理到底是什么？

**A：**核心原理是：**DWARF 保存的不是“参数值”，而是“参数在某个 PC 点位于哪里”。**

也就是说，Stage-2 真正做的是两步：

1. **先定位当前帧在源码语义里属于哪个函数/哪个 PC；**
2. **再解释这个 PC 下参数的 location expression。**

举例来说，DWARF 可能告诉你某个参数当前位于：

- 某个寄存器；
- `rbp - 0x20`；
- `CFA + 0x18`；
- 或者一个更复杂、当前实现尚不支持的表达式。

于是 Stage-2 需要把 crash-time 证据代入这个“位置描述”里：

- 有寄存器值，就直接读寄存器；
- 有 `frame_fp`，就把它当成 `frame_base` fallback；
- 能推出 `CFA`，就支持 `DW_OP_call_frame_cfa`；
- 地址刚好落在 `stack_window` 里，就去读快照里的那段栈副本；
- 如果表达式太复杂，或者地址超出 `stack_window`，就诚实降级。

所以它不是“凭空推测 older frame 的参数”，而是：**用崩溃时保留下来的少量机器状态，去解释 debuginfo 里已经存在的位置规则。**

**实现对应代码位置：**

- 初始化参数求值上下文：`agent/src/ebpf/user/crash_symbolize.c:1345`
- 按 DWARF 寄存器号取值：`agent/src/ebpf/user/crash_symbolize.c:965`
- 简化 `CFA` 推导：`agent/src/ebpf/user/crash_symbolize.c:1360`
- DWARF location expression 求值：`agent/src/ebpf/user/crash_symbolize.c:1418`
- 递归解析 `DW_AT_location` / `DW_AT_frame_base`：`agent/src/ebpf/user/crash_symbolize.c:1684`
- `frame_base` 准备与 `frame_fp` fallback：`agent/src/ebpf/user/crash_symbolize.c:1742`
- 单参数恢复：`agent/src/ebpf/user/crash_symbolize.c:1810`

#### Q3：可以用 Stage-1 / Stage-2 的方式怎么描述？

**A：**可以直接这样理解：

**Stage-1：fatal signal context，只做证据保全**

- 运行在 `SIGSEGV` / `SIGABRT` / `SIGBUS` / `SIGILL` / `SIGFPE` handler 中；
- 从 `ucontext_t` 里抓 top-frame 的 `ip/sp/fp/lr`、`args[]` 与 full regs；
- 做有界 frame-pointer walk，记录 `absolute_pc`、`frame_fp`、`frame_flags`；
- 给每帧注释 `module_index + rel_pc`；
- 复制有界 `stack_window`；
- 以固定大小二进制 record 直接 `write()` 落盘；
- 然后恢复默认信号行为并重新抛出原始 signal。

**Stage-2：normal context，负责解释这些证据**

- 在下一次正常启动时读取旧 snapshot；
- 按 `module_index + rel_pc` 重建稳定的 ELF / DWARF PC；
- 打开原始模块或外部 debuginfo，恢复 `symbol`、`file:line`；
- 找到 `DW_TAG_subprogram` 与 `DW_TAG_formal_parameter`；
- 准备 `frame_base` / 简单 `CFA`，解释 `DW_AT_location`；
- 能读出值就输出值，读不出就输出 location 或 `<unavailable>`；
- 最后输出人类可读日志并清空已消费的 `.crash` 文件。

一句话概括就是：

> **Stage-1 负责“保住现场”，Stage-2 负责“解释现场”。**

**实现对应代码位置：**

- Stage-1 初始化入口：`agent/src/ebpf/user/crash_monitor.c:1275`
- Stage-1 每线程 altstack 准备：`agent/src/ebpf/user/crash_monitor.c:1260`
- Stage-1 安装 fatal signal handlers：`agent/src/ebpf/user/crash_monitor.c:989`
- Stage-1 fatal signal handler：`agent/src/ebpf/user/crash_monitor.c:940`
- Stage-1 从 `ucontext_t` 填充 record：`agent/src/ebpf/user/crash_monitor.c:825`
- Stage-1 采集 `stack_window` / registers / frame walk：`agent/src/ebpf/user/crash_monitor.c:564`、`agent/src/ebpf/user/crash_monitor.c:594`、`agent/src/ebpf/user/crash_monitor.c:765`
- Stage-1 把 record 追加写盘：`agent/src/ebpf/user/crash_monitor.c:973`
- Stage-2 启动期消费旧快照入口：`agent/src/ebpf/user/crash_monitor.c:1212`
- Stage-2 单帧符号化：`agent/src/ebpf/user/crash_symbolize.c:2710`
- Stage-2 `file:line` / params 恢复：`agent/src/ebpf/user/crash_symbolize.c:2572`、`agent/src/ebpf/user/crash_symbolize.c:2442`

#### Q4：Stage-1 保存的 `frame_fp` 都是绝对地址，到了 Stage-2，怎么利用这些地址去读取二进制文件的 debuginfo？

**A：**这里最关键的一点是：**Stage-2 并不是用 `frame_fp` 去定位 debuginfo。**

真正用于 debuginfo 查找的主链路是：

1. 先用 `frame->module_index` 找到 snapshot 里记录的模块；
2. 再用 `frame->rel_pc` 计算：

   ```c
   file_offset_pc = module->file_offset + frame->rel_pc;
   ```

3. 然后把这个 file-relative PC 转换成 ELF 虚拟地址：

   ```c
   elf_vaddr = phdr.p_vaddr + (file_offset - phdr.p_offset);
   ```

4. 后续的 ELF symbol、DWARF line、`DW_TAG_subprogram`、`DW_AT_location` 匹配，都是围绕这个 `elf_vaddr` 展开的。

也就是说：

- **用于进入 debuginfo 世界的是 `module_index + rel_pc`；**
- **不是 `frame_fp`。**

`frame_fp` 保存为绝对地址，作用在另外一个维度：它仍然属于“崩溃时线程栈地址空间”的证据，主要用于：

- `DW_AT_frame_base` 缺失时，作为 frame base fallback；
- 计算简单 `CFA`；
- 解释 `DW_OP_fbreg` 这类基于 frame base 的位置表达式；
- 把 `frame_fp + offset` 之类的位置落回 snapshot 的 `stack_window` 中读取真实值。

换句话说，Stage-2 同时在处理两套地址语义：

1. **代码地址语义**
   - 用 `module_index + rel_pc -> file_offset_pc -> elf_vaddr` 进入 ELF / DWARF；
2. **栈地址语义**
   - 用绝对 `frame_fp`、`sp`、`stack_window_start` 去解释参数位于哪一段 crash-time 栈内存。

所以“absolute `frame_fp` 到底怎么用于 debuginfo”这个问题，最准确的回答其实是：

> **它不直接用于 debuginfo 定位；它用于在 Stage-2 解释 DWARF location 时，重建该帧的栈语义。真正把帧映射回 debuginfo 的，是 `module_index + rel_pc`。**

**实现对应代码位置：**

- Stage-1 用绝对 `absolute_pc` 标注 `module_index + rel_pc`：`agent/src/ebpf/user/crash_monitor.c:467`
- Stage-2 通过 `module_index` 找模块：`agent/src/ebpf/user/crash_symbolize.c:546`
- Stage-2 对 non-top frame 做 PC 归一化：`agent/src/ebpf/user/crash_symbolize.c:668`
- Stage-2 计算 `file_offset_pc` 并驱动单帧符号化：`agent/src/ebpf/user/crash_symbolize.c:2710`
- Stage-2 把 file-relative PC 转成 `elf_vaddr`：`agent/src/ebpf/user/crash_symbolize.c:682`
- ELF program header 中 `file_offset -> vaddr` 转换：`agent/src/ebpf/user/elf.c:618`
- Stage-2 读取 `frame_fp`：`agent/src/ebpf/user/crash_symbolize.c:853`
- Stage-2 从 `stack_window` 按绝对地址读值：`agent/src/ebpf/user/crash_symbolize.c:878`
- Stage-2 用 `frame_fp` 计算简单 `CFA`：`agent/src/ebpf/user/crash_symbolize.c:1360`
- Stage-2 用 `frame_fp` 作为 `frame_base` fallback：`agent/src/ebpf/user/crash_symbolize.c:1742`

---

## 15. 当前能力总结



当前 crash monitor 已具备以下能力：

- fatal signal handler 安装；
- 每线程 altstack 准备；
- 顶层崩溃元数据抓取；
- top-frame ABI 参数寄存器抓取；
- v4 完整 top-frame 通用寄存器块持久化；
- 普通栈边界缓存；
- bounded stack window 持久化；
- frame-pointer 有界回溯；
- AArch64 LR hint 记录；
- `frame_fp` / `frame_flags` 持久化；
- `/proc/self/maps` 模块缓存；
- `module_index + rel_pc` 注释；
- 固定路径二进制快照写盘；
- v2 / v3 / v4 快照兼容消费；
- 启动期旧快照消费；
- crash summary 中的 task 名、可执行文件路径与 MD5 输出；
- Stage-2 完整寄存器 / partial 寄存器日志；
- Stage-2 top-frame args 日志；
- Stage-2 ELF symbol 解析；
- Stage-2 DWARF `file:line` 解析；
- build-id aware external debuginfo 查找；
- per-frame formal parameter 枚举；
- 受限 DWARF location expression 求值；
- stack-window-backed 参数值恢复；
- per-frame `params:` 日志输出；
- best-effort 多层级日志降级输出。

换句话说，当前实现已经不是“只能打印原始地址的快照消费者”，而是一个完整的：

- **Stage-1 原始崩溃现场采集器**
- **Stage-2 best-effort 崩溃符号化器与参数恢复器**

---

## 16. 总结

整个设计的核心思想可以概括为一句话：

> **崩溃当下只保全证据；复杂分析必须延后到正常上下文。**

围绕这一原则，当前实现已经形成完整闭环：

1. 运行前预缓存模块、线程名和线程普通栈边界；
2. 为主线程与 monitored worker thread 准备 altstack；
3. 崩溃时以 async-signal-safe 风格保存固定大小 v4 快照；
4. 快照中持久化模块、帧、full regs、stack window 等原始证据；
5. 下次启动时兼容消费 v2/v3/v4 记录；
6. 基于 build-id、ELF、DWARF 做 best-effort 符号化；
7. 输出 crash summary、完整寄存器、top-frame args、逐帧日志和 per-frame 参数；
8. 清空已消费快照，继续本次运行。

这保证了：

- 原始崩溃语义不被破坏；
- signal handler 保持足够克制；
- Stage-2 可以不断增强，而无需把复杂逻辑塞回 fatal path。
