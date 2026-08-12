# JVM `JvmtiExport::post_compiled_method_load` SIGSEGV 排查报告

## 1. 报告信息

| 项目 | 内容 |
| --- | --- |
| 排查对象 | DeepFlow Java 符号采集 JVMTI Agent |
| 相关源码 | `agent/src/ebpf/user/profile/java/symbol_collect_agent.c` |
| 崩溃日志 | `/root/.codex/attachments/be17d8a7-bfd4-441e-aed5-5d2e8db4e2d7/pasted-text.txt` |
| JVM | OpenJDK 64-Bit Server VM 8u342-b07 |
| 操作系统 | Kylin Linux Advanced Server V10，Linux 5.10，x86_64 |
| 排查日期 | 2026-08-06 |
| 结论置信度 | 高 |

## 2. 结论摘要

本次 SIGSEGV 的直接原因，高置信度属于旧版 HotSpot 的 JVMTI `CompiledMethodLoad` 已知缺陷，而不是 `symbol_collect_agent.c` 回调函数直接发生越界写或空指针访问。

DeepFlow Agent 申请并启用了 `JVMTI_EVENT_COMPILED_METHOD_LOAD`，因此它是该 JVM 缺陷的触发条件。旧版 HotSpot 将待通知的 `nmethod` 放入延迟事件队列后，没有在 GC、类卸载和 CodeCache Sweeper 执行期间完整保护其方法元数据。等 `Service Thread` 处理事件时，相关 `nmethod` 可能已经被卸载、清理或转为 zombie，HotSpot 随后在构造 JVMTI 回调参数、解析内联信息时解引用失效元数据，最终访问空指针偏移 `0x8`。

该问题与 OpenJDK 已知缺陷 [JDK-8173361](https://bugs.openjdk.org/browse/JDK-8173361) 的崩溃特征高度一致。它首次回移至 OpenJDK 8u352，见 [JDK-8289478](https://bugs.openjdk.org/browse/JDK-8289478)；8u 回移中与 Sweeper 保护相关的问题又在 8u382 通过 [JDK-8305165](https://bugs.openjdk.org/browse/JDK-8305165) 补齐。因此，版本范围不能简单写成“所有低于 8u382 的版本都已经复现”，而应区分“已确认缺少首个修复”和“补丁尚未完整”的版本段。对于标准 OpenJDK 8，当前完整修复基线仍是 8u382。

同时，`symbol_collect_agent.c` 的 socket 发送和重复 attach 状态切换存在并发、忙等待等问题。这些问题无法解释本次发生在 `libjvm.so` 内部、进入 Agent 回调之前的空指针崩溃，但可能阻塞 JVM `Service Thread`、增加延迟事件积压，从而显著放大旧 JVM 缺陷的触发概率。

## 3. 通俗版说明

### 3.1 是什么问题

可以把 JVM 编译出来的机器码理解成一批“临时生成的代码卡片”。每张卡片记录了代码地址、对应的 Java 方法以及方法的内联关系。

DeepFlow Agent 为了把采样地址还原成 Java 方法名，会要求 JVM 在生成新卡片时通知它。JVM 没有立刻发送所有通知，而是先把一部分通知放进队列，之后由 `Service Thread` 处理。

这次的问题是：某张卡片已经被 JVM 回收或清理了，通知却还留在队列中。`Service Thread` 后来处理这条旧通知时，继续读取已经失效的卡片，最终访问了空指针地址 `0x8`，导致整个 JVM 段错误退出。

简单概括：

> JVM 准备把一条 JIT 方法信息通知给 DeepFlow 时，这条信息已经被 JVM 自己回收，但旧版 JVM 仍继续访问它，因此崩溃。

### 3.2 根因是什么

根因是 OpenJDK 8u342 中 HotSpot 对 JVMTI 延迟 `CompiledMethodLoad` 事件的生命周期保护不完整。

正常情况下，只要某个已编译方法的通知还在队列中，JVM 就应该保证对应的 `nmethod` 和方法元数据不能被 GC、类卸载或 CodeCache Sweeper 清理。8u342 没有完整做到这一点，因此存在以下竞态：

```text
JIT 生成 nmethod
    -> JVM 将 CompiledMethodLoad 通知放入队列
    -> GC、类卸载或 Sweeper 清理该 nmethod/方法元数据
    -> Service Thread 取出旧通知
    -> JVM 读取失效元数据
    -> SIGSEGV
```

这是 OpenJDK 已确认并修复的缺陷，不是 Java 业务代码中的 `addAll()` 引起的，也没有证据表明是 DeepFlow 回调直接写坏了 JVM 内存。

### 3.3 Agent 的触发条件是什么

这是一个并发时序型 JVM 缺陷。触发崩溃需要以下几个条件在同一时间窗口内成立：

1. JVM 版本存在缺陷。本次使用的是 OpenJDK 8u342，尚未包含相关 HotSpot 修复。
2. DeepFlow Agent 已成功加载，并启用 `JVMTI_EVENT_COMPILED_METHOD_LOAD`。
3. JVM 进行 JIT 编译，生成新的 `nmethod`，随后将方法加载通知放入 JVMTI 延迟事件队列。
4. `Service Thread` 处理通知前，对应的 `nmethod` 或方法元数据已经失效，例如因 GC、类卸载，或者在类重定义、去优化后被 CodeCache Sweeper 清理。
5. `Service Thread` 取出这条旧通知，HotSpot 在调用 DeepFlow 回调前继续解析失效元数据，最终发生空指针访问并触发 SIGSEGV。

完整触发链如下：

```text
DeepFlow Agent 启用 CompiledMethodLoad
    -> JIT 生成 nmethod
    -> HotSpot 将事件放入 JVMTI 延迟队列
    -> GC、类卸载、去优化或 Sweeper 使相关元数据失效
    -> Service Thread 延迟处理旧事件
    -> HotSpot 访问失效元数据
    -> SIGSEGV
```

#### 为什么压力测试更容易触发

压力测试不会产生新的根因，但会让上述事件更密集地发生，从而显著增大竞态窗口：

- 热点代码执行频繁，JIT 编译量增加，产生更多 `CompiledMethodLoad` 事件；
- CodeCache 增长更快，Sweeper 更频繁地清理旧 `nmethod`；
- 对象分配量增加，GC 更活跃；
- 类重定义、retransformation 和去优化会加速旧编译代码失效；
- DeepFlow 需要发送的符号量增加，符号 socket 更容易出现背压；
- `send_msg()` 遇到 `EAGAIN` 时无限重试，可能阻塞 `Service Thread`，造成 JVMTI 事件队列积压；
- 多次重复 attach Agent 会增加状态切换和并发处理的复杂度。

本次日志也符合这一过程：崩溃前先后出现 GC、MemCheck 类重定义、去优化和多次 `flushing nmethod`，随后 `Service Thread` 在 `post_compiled_method_load` 中崩溃。

因此，只在压力测试中发现是符合预期的。非压力环境下竞态窗口较小，所以可能长时间不出现，但不代表问题不存在。DeepFlow Agent 启用了问题路径，并可能通过回调阻塞放大触发概率；真正的根因仍是旧版 HotSpot 没有正确保护延迟事件引用的 `nmethod` 生命周期。

### 3.4 如何解决

根本解决方案是升级或修补 JVM：

1. 优先升级到厂商当前受支持的最新 JDK 8，或者升级到受支持的 JDK 11/17。
2. 如果继续使用 JDK 8，确认厂商版本包含以下两个修复或等价补丁：
   - `JDK-8173361`，OpenJDK 8u 首次回移到 8u352；
   - `JDK-8305165`，在 8u382 补齐 8u 特有的 Sweeper 保护问题。
3. 最低建议验证基线为 8u382，不建议只升级到 8u352 后就认为问题完全解决。
4. 无法更换 JVM 二进制时，可向当前厂商 JDK 回移 OpenJDK 提交 `1b4f32d6` 和 `3147b1ba`。

同时应修复 DeepFlow Agent，降低它对 JVM 内部线程的影响：

- `EAGAIN` 时不能无限忙等待，应有超时和丢弃策略；
- callback 必须有明确的最大执行时间；
- 重复 attach 和 callback 之间需要完整的生命周期同步；
- 修复日志发送长度越界读取和 `SIGPIPE` 处理。

需要强调：只修改 Agent 的 socket 代码可以降低复现概率，但不能修复旧 JVM 对 `nmethod` 生命周期管理错误，不能作为根治方案。

### 3.5 如何临时规避

无法立即升级 JVM 时，可按影响从小到大选择以下措施：

1. 暂停或降低 MemCheck 等 Agent 的类重定义、retransformation 频率，减少方法失效和去优化。
2. 保证 DeepFlow 符号 socket 接收端持续、及时消费数据，避免 socket 背压阻塞 JVM `Service Thread`。
3. 避免对同一 JVM 重复 attach DeepFlow Agent。
4. 修改 DeepFlow Agent，不再持续启用 `JVMTI_EVENT_COMPILED_METHOD_LOAD`。这样会丢失后续新产生的 JIT 方法符号，Java profiling 结果可能出现无法符号化的地址。
5. 最可靠的止血方案是停止向受影响 JVM 注入 DeepFlow Java symbol Agent。此时 DeepFlow 不再触发这条 JVMTI 路径，但会失去或降低 Java JIT 符号化能力。

临时规避只能减少或消除触发条件，不能消除 JVM 中原有的缺陷。只要旧 JVM 上还有其他 JVMTI Agent 启用同类事件，理论上仍可能触发。

## 4. 事故现象

崩溃日志的核心信息如下：

```text
SIGSEGV (0xb) at pc=0x00007f9744187dfe, pid=1, tid=0x00007f9701dfd700
JRE version: OpenJDK Runtime Environment (8.0_342-b07)
Problematic frame:
V  [libjvm.so+0x7fcdfe]  JvmtiExport::post_compiled_method_load(nmethod*)+0x24e

Current thread:
JavaThread "Service Thread" daemon [_thread_in_vm]

siginfo:
si_code: SEGV_MAPERR
si_addr: 0x0000000000000008

RAX=0x0000000000000000
```

崩溃指令为：

```text
48 8b 40 08    mov 0x8(%rax), ...
```

此时 `RAX=0`，所以 CPU 实际访问地址为 `NULL + 0x8`，与日志中的 `si_addr=0x8` 完全一致。这是典型的 JVM 内部对象或元数据空指针成员访问。

native 调用栈为：

```text
JvmtiExport::post_compiled_method_load(nmethod*)
ServiceThread::service_thread_entry(JavaThread*, Thread*)
JavaThread::thread_main_inner()
JavaThread::run()
java_start(Thread*)
```

调用栈中没有出现以下 DeepFlow Agent 函数：

```text
cbCompiledMethodLoad()
generate_single_entry()
df_send_symbol()
send_msg()
```

这说明本次崩溃发生在 HotSpot 准备和分发 JVMTI 事件的过程中，尚未进入 DeepFlow 的 `CompiledMethodLoad` 回调。

## 5. 事件时间线

根据 `hs_err` 日志，可整理出以下相对时间线：

| JVM 运行时间 | 事件 |
| ---: | --- |
| 240.511 秒 | G1 GC 开始 |
| 240.540 秒 | G1 GC 完成 |
| 244.575 秒 | MemCheck Agent 重定义 `com.qt.memchk.MemCheck$b` |
| 247.754 秒 | MemCheck Agent 重定义 `com.qt.memchk.common.f` |
| 252.581 秒 | HotSpot 连续执行多次 `flushing nmethod` |
| 252.675～252.679 秒 | JVM 继续产生新的编译事件和 `nmethod` |
| 252.878 秒 | `Service Thread` 在 `post_compiled_method_load` 中崩溃 |

崩溃前同时存在 GC、类重定义、去优化和 `nmethod` 清理活动，与已知缺陷中“延迟事件持有的 `nmethod` 在事件处理前失效”的触发条件一致。

日志寄存器中出现的 `java/util/AbstractCollection.addAll` 是 HotSpot 当时正在解析的方法元数据上下文，不表示 Java 业务代码中的 `addAll()` 实现有问题。

## 6. DeepFlow Agent 与崩溃路径的关系

### 6.1 Agent 确实已加载

进程内存映射中存在：

```text
/deepflow/df_java_agent_v2.so (deleted)
```

`(deleted)` 只表示 Agent 临时文件在 `dlopen()` 后从文件系统删除。其代码段仍保留在 JVM 地址空间且具有可执行映射，并不表示共享库已经从进程卸载，也不能据此判断为回调指针悬空。

### 6.2 Agent 启用了问题事件

`symbol_collect_agent.c` 中的关键调用为：

1. 申请 `CompiledMethodLoad` 能力：

   ```c
   capabilities.can_generate_compiled_method_load_events = 1;
   ```

   位置：`symbol_collect_agent.c:283`

2. 注册 DeepFlow 回调：

   ```c
   callbacks.CompiledMethodLoad = &cbCompiledMethodLoad;
   ```

   位置：`symbol_collect_agent.c:423`

3. 启用持续通知：

   ```c
   (*jvmti)->SetEventNotificationMode(
       jvmti, mode, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL);
   ```

   位置：`symbol_collect_agent.c:441-443`

4. 回放当前已编译方法：

   ```c
   (*jvmti)->GenerateEvents(
       jvmti, JVMTI_EVENT_COMPILED_METHOD_LOAD);
   ```

   位置：`symbol_collect_agent.c:498-499`

持续通知会使新生成的 `nmethod` 通过 HotSpot 的 JVMTI 延迟事件队列交给 `Service Thread`。本次崩溃发生在 `Service Thread`，因此更符合持续编译事件的异步分发路径，而不是 `Agent_OnAttach` 线程中同步执行初始回放的路径。

### 6.3 Agent 是触发者，不是本次直接崩溃点

因果关系应表述为：

```text
DeepFlow Agent 启用 CompiledMethodLoad
    -> HotSpot 将 nmethod 放入 JVMTI 延迟事件队列
    -> GC、类卸载或 Sweeper 使 nmethod/Method 元数据失效
    -> Service Thread 延后处理该事件
    -> HotSpot 在调用 DeepFlow 回调前解析失效元数据
    -> NULL + 0x8，JVM SIGSEGV
```

若不加载任何需要 `CompiledMethodLoad` 的 JVMTI Agent，这条 HotSpot 缺陷路径通常不会被触发。但这不等于 Agent 回调代码写坏了 JVM 内存。

## 7. 与 OpenJDK 已知缺陷的匹配

### 7.1 JDK-8173361 / JDK-8289478

[JDK-8173361](https://bugs.openjdk.org/browse/JDK-8173361) 记录了 `JvmtiExport::post_compiled_method_load` 中的多种崩溃。其公开案例包含以下共同特征：

- 崩溃线程为 `Service Thread`；
- 崩溃发生在 `JvmtiExport::post_compiled_method_load` 或其内联的 `create_inline_record`、`ScopeDesc` 解析路径；
- `nmethod` 已经被卸载，或其 `_method`、`jmethodID` 已被清空；
- 可出现 `SEGV_MAPERR` 和访问地址 `0x8`；
- JVMTI Agent 开启了 `COMPILED_METHOD_LOAD` 事件。

OpenJDK 8u 的回移缺陷号为 [JDK-8289478](https://bugs.openjdk.org/browse/JDK-8289478)，修复进入 OpenJDK 8u352，对应提交：

- [openjdk/jdk8u@1b4f32d6](https://github.com/openjdk/jdk8u/commit/1b4f32d61e3b0460c82598f24dbd5c4dd0fc3bbe)

该补丁的核心目标是让 `Service Thread` 和 JVMTI 延迟队列在 GC、代码清理期间正确暴露和保护待处理的 `nmethod`，避免使用已经卸载的方法元数据。

### 7.2 JDK-8305165

8u352 的回移在 JDK 8 中仍存在特殊问题：`JavaThread::nmethods_do()` 不是虚函数，导致遍历 Java 线程时没有调用 `ServiceThread::nmethods_do()`，队列中的 `nmethod` 仍可能被 Sweeper 转为 zombie。

该问题通过 [JDK-8305165](https://bugs.openjdk.org/browse/JDK-8305165) 在 OpenJDK 8u382 修复，对应提交：

- [openjdk/jdk8u@3147b1ba](https://github.com/openjdk/jdk8u/commit/3147b1bafe12326a97269655de46f066931f3ee4)

本次环境为 8u342，早于上述两个修复，因此完全处于受影响版本范围内。仅凭 `hs_err` 无法进一步确定本次失效属于类卸载还是 Sweeper zombification；二者属于同一缺陷链，处置方案一致。

### 7.3 Java 8 版本范围与证据等级

根据 OpenJDK 8 的发布说明和补丁回移关系，标准 OpenJDK HotSpot Java 8 应按以下三个范围理解：

| Java 8 update 范围 | 补丁状态 | 结论与证据等级 |
|---|---|---|
| `8u0–8u351` | 尚未包含 JDK-8173361/JDK-8289478 | 高风险范围；本次客户 `8u342-b07` 属于此段，并已在相同压力模型中由 Honest Profiler 和 DeepFlow 均复现 |
| `8u352–8u381` | 已包含 JDK-8173361，但尚未包含 JDK-8305165 | 部分修复、残余风险范围；不能称为“已确认必现”，也不能仅凭版本号称为完整安全 |
| `8u382` 及更高 | 两个修复均已进入标准 OpenJDK 8 | 当前完整修复基线；本机 `8u382-b05` 在两种 Agent 和相同压力下均跑满 300 秒未复现 |

这里的“高风险范围”表示标准 OpenJDK 发行版明确缺少对应修复，不表示每一个 update 在任何负载下都会崩溃；竞态型缺陷仍取决于 JIT、类卸载、Sweeper 和 JVMTI 事件时序。相反，`8u352–8u381` 不能因为尚未收集到每个 update 的崩溃样本就直接判定安全，原因是该段仍缺少 8u 特有的 Sweeper 保护修复。

因此，当前代码中的 `update < 382` 是“补丁完整性门禁”，不是“所有低于 382 的版本都已被逐一证明必现”的结论。若要把 `8u352–8u381` 改为允许 attach，至少还需要对目标厂商的具体构建确认包含 JDK-8305165 或等价补丁，或者完成同一压力矩阵的版本级验证；仅依赖 `JAVA_VERSION` 的 update 数字无法识别厂商是否额外回移了补丁。

## 8. `symbol_collect_agent.c` 中发现的风险

以下问题不是本次 SIGSEGV 的直接根因，但建议同步整改。

### 8.1 非阻塞 socket 遇到 `EAGAIN` 时无限忙等待

代码位置：`symbol_collect_agent.c:95-101`

```c
if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
    continue;
}
```

socket 被设置为 `O_NONBLOCK`，但出现发送背压后立即无限重试，实际效果是忙等待。对于正常的新编译事件，回调可能运行在 JVM `Service Thread` 上；一旦接收端消费较慢，该线程会长时间占用 CPU 并停止消费 JVMTI 延迟队列。

这会产生两个后果：

- JVM 内部服务事件处理延迟；
- 更多 `nmethod` 长时间停留在延迟队列中，显著扩大旧版 HotSpot 生命周期缺陷的竞态窗口。

建议改为有上限的重试或 `poll()` 等待，并设置严格超时；符号采集不能以无限期阻塞 JVM 内部线程为代价。达到超时后应记录丢包并返回。

### 8.2 重复 attach 的全局状态切换没有统一同步

代码位置：`symbol_collect_agent.c:513-548`

重复 attach 时会执行：

- 关闭旧 socket；
- 禁用和重新启用 JVMTI 事件；
- 修改 `g_jvmti`、`replay_finish`、`replay_count`；
- 清零 `g_cached_bytes`；
- 创建新 socket 并重新回放符号。

以上操作没有全部纳入 `g_df_lock` 或独立的生命周期锁，而 JVMTI 回调可能同时在其他 JVM 线程上运行。潜在影响包括：

- callback 使用已经关闭或被复用的 fd；
- 回放缓存被并发清零，造成符号丢失或协议流损坏；
- C 语言层面的无同步数据竞争；
- 新旧 attach 周期的数据写入同一个新 fd。

这类问题更可能表现为符号错误、socket 异常或 Agent 自身崩溃，不符合当前 `libjvm.so` 内部空指针特征。

### 8.3 `df_log` 使用未截断的 `snprintf()` 返回值

代码位置：`symbol_collect_agent.c:82-85`

```c
char str_buf[LOG_BUF_SZ];
int n = snprintf(str_buf, sizeof(str_buf), format, ...);
send_msg(perf_map_log_socket_fd, str_buf, n);
```

当输出超过 511 字节时，`snprintf()` 返回原本需要写入的长度，该长度可能大于 `str_buf`，随后 `send_msg()` 会越界读取栈内存。发送长度应限制在实际缓冲区内容范围内，并处理负返回值。

### 8.4 非阻塞模式不能避免 `SIGPIPE`

源码注释认为 `O_NONBLOCK` 能避免向关闭 socket 写入时产生 `SIGPIPE`，该判断不成立。非阻塞模式只改变阻塞行为，不会禁止 `SIGPIPE`。应使用 `MSG_NOSIGNAL`，或明确、审慎地管理进程级信号策略。

本次信号为 `SIGSEGV`，不是 `SIGPIPE`，所以该问题与本次事故无直接关系。

## 9. 根因分层

| 层级 | 结论 | 说明 |
| --- | --- | --- |
| 直接原因 | HotSpot 解引用失效的 `nmethod`/Method 元数据 | 发生于 `post_compiled_method_load` 内部、进入 Agent 回调之前 |
| 产品触发条件 | DeepFlow Agent 启用 `JVMTI_EVENT_COMPILED_METHOD_LOAD` | 没有该事件需求时通常不会走到问题路径 |
| 环境根因 | OpenJDK 8u342 缺少已知修复 | 早于 8u352 和 8u382 的相关补丁 |
| 概率放大因素 | Agent socket 忙等待、类重定义、GC、CodeCache 清理 | 延长队列停留时间或增加 nmethod 失效机会 |
| 已排除的主要方向 | DeepFlow callback 当前栈内直接越界或空指针 | native 栈没有进入 Agent `.so` |

## 10. 处置建议

### 10.1 立即措施

1. 将 JVM 升级到包含 `JDK-8173361` 和 `JDK-8305165` 修复的厂商版本。
2. 对 OpenJDK 8，建议直接升级到当前受支持的最新更新版；最低验证基线应为 8u382，而不是仅停留在 8u352。
3. 厂商 JDK 的补丁集合可能与 OpenJDK 版本号不完全一致，应向厂商确认是否包含以下修复或等价补丁：
   - `JDK-8173361` / 提交 `1b4f32d6`；
   - `JDK-8305165` / 提交 `3147b1ba`。
4. 若暂时无法升级，事故止血方案是停止向受影响 JVM 注入 DeepFlow Java symbol Agent，代价是失去 JIT Java 符号化能力。

### 10.2 短期代码整改

1. 修复 `send_msg()` 的 `EAGAIN` 无限循环，为 JVM 回调设置有界执行时间。
2. 为 `Agent_OnAttach`、socket fd 和回放缓存增加一致的生命周期同步。
3. 修复 `df_log` 发送长度越界读取。
4. 使用 `MSG_NOSIGNAL` 或等价机制处理 socket `SIGPIPE`。
5. 增加指标：callback 耗时、发送失败数、EAGAIN 次数、符号丢弃数、重复 attach 次数。

### 10.3 无法升级 JVM 时的源码回移

如果必须继续使用现有厂商 8u342，可在 HotSpot 中回移以下 OpenJDK 提交并重新构建 JVM：

1. `1b4f32d61e3b0460c82598f24dbd5c4dd0fc3bbe`；
2. `3147b1bafe12326a97269655de46f066931f3ee4`。

只修改 Agent 无法从根本上保证安全，因为 Agent 无权控制 HotSpot 延迟队列中 `nmethod` 的 GC 和 Sweeper 生命周期。

## 11. 验证方案

### 11.1 推荐 A/B 验证矩阵

| 场景 | JVM | DeepFlow Agent | 预期 |
| --- | --- | --- | --- |
| A | 当前 8u342 | 开启 | 在高编译、类重定义、socket 背压下可能复现 |
| B | 当前 8u342 | 关闭 | DeepFlow 触发路径消失；其他 JVMTI Agent 仍可能启用同类事件 |
| C | 包含两个修复的新版 JDK | 开启 | 不再发生该类 `post_compiled_method_load` 崩溃 |
| D | 新版 JDK | 开启并注入 socket 背压 | JVM 不应崩溃，但可用于暴露 Agent callback 阻塞问题 |

场景 C 是验证根因和解决方案的关键。仅通过场景 B 不能证明 Agent 回调存在内存破坏，只能证明它提供了事件触发条件。

### 11.2 压力条件

建议组合以下负载持续验证：

- 高频 JIT 编译和 CodeCache 清理；
- G1 周期性 GC；
- 与当前 MemCheck Agent 相同的类重定义或 retransformation；
- DeepFlow 符号 socket 接收端限速、短时暂停或主动断开；
- 重复执行 Agent attach；
- 运行时间覆盖历史故障窗口，并进一步延长。

### 11.3 Core dump 深度确认

若保留了 `/ebcpa/core` 和完全匹配的 `/jdk8/jre/lib/amd64/server/libjvm.so`，可使用带 HotSpot 调试符号的 GDB 环境进一步确认：

- `JvmtiExport::post_compiled_method_load` 的精确源码行；
- 待通知 `nmethod` 的状态；
- `nmethod->_method`、内联 `ScopeDesc` 或 `jmethodID` 是否已清空；
- 该事件是否仍处于 `JvmtiDeferredEventQueue`；
- 崩溃前是否发生 class unloading 或 Sweeper zombification。

该步骤可以将“高置信度匹配已知缺陷”提升为对具体失效字段的确定性结论，但不影响当前升级 JVM 的处置建议。

## 12. 验收标准

完成整改后应满足：

1. 生产 JVM 明确包含 `JDK-8173361` 和 `JDK-8305165` 或厂商等价修复。
2. 压力测试期间不再出现 `JvmtiExport::post_compiled_method_load`、`create_inline_record`、`ScopeDesc` 等相关崩溃。
3. DeepFlow JVMTI callback 在 socket 背压时有明确的最大执行时间，不无限忙等待。
4. 重复 attach 与并发 callback 不发生 fd 复用、缓存损坏或数据竞争。
5. 可通过指标观察符号丢弃和 socket 背压，而不是阻塞 JVM 内部线程。

## 13. 最终判断

本次事故应归类为：

> DeepFlow Java 符号采集 Agent 启用 JVMTI `CompiledMethodLoad` 后，触发 OpenJDK 8u342 中已知的延迟 `nmethod` 生命周期缺陷；Agent 的同步发送实现可能扩大竞态窗口，但没有证据表明本次 SIGSEGV 是由 Agent 回调中的直接内存破坏造成。

根本解决方案是升级或修补 HotSpot；同时应整改 Agent 的 callback 阻塞和重复 attach 并发问题，以降低对 JVM 内部服务线程的影响。
