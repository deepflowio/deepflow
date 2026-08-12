# Java attach 前置检查说明

## 1. 这项检查是做什么的

DeepFlow 在采集 Java 符号前，需要把一个 JVMTI Agent 加载到目标 JVM 中。这个动作叫作 `attach`。

旧版 HotSpot，特别是本次客户环境中的 Java 8u342，在处理 `CompiledMethodLoad` 事件时存在已知缺陷。Agent 一旦打开这个 JVM 能力，在高频 JIT 编译、类加载和类卸载同时发生时，可能触发 JVM 崩溃。版本范围需要分段理解：`8u0–8u351` 缺少首个已知修复，`8u352–8u381` 虽然已有第一组修复但仍缺少 8u 特有的 Sweeper 保护，`8u382` 起才包含完整补丁链。当前代码使用 `8u382` 作为完整修复门禁，因此这是保守的补丁完整性判断，不是声称所有低于 8u382 的版本都已逐一复现。

因此，代码现在会在 attach 之前先检查目标 JVM：

```text
检查目标进程
    -> 判断 JVM 类型
    -> 仅对 HotSpot 检查版本
    -> 检查 attach 是否被禁用
    -> 再次确认 PID 没有变化
    -> 通过后才执行 attach
```

这项检查只读取本机的 `/proc` 文件和目标 JVM 文件，不访问第三方系统。

## 2. 检查从哪里开始

公共检查入口是：

```c
java_attach_preflight(pid, &info)
```

有两个地方会调用它：

1. `start_java_symbol_collection()`：在创建线程池和 socket 之前检查；
2. `java_attach()`：在准备 Agent SO、切换 namespace 和执行 jattach 之前再次检查。

第二次检查是为了防止第一次检查结束后，目标 JVM 在真正 attach 前发生变化。

## 3. 检查顺序

### 第一步：确认进程还活着

代码读取 `/proc/<pid>/stat`，确认：

- PID 存在；
- 进程不是已经退出的进程；
- 进程不是僵尸进程；
- 能够读取进程的启动时间和可执行文件路径。

如果目标已经退出，继续 attach 没有意义，会直接跳过。

### 第二步：判断 JVM 类型

代码读取 `/proc/<pid>/maps`：

- 找到 `libjvm.so`，认为是 HotSpot；
- 找到 `libj9vm`，认为是 OpenJ9；
- OpenJ9 即使同时映射了兼容性的 `libjvm.so`，也优先按 OpenJ9 处理；
- 两种 JVM 核心库都找不到时，不确认目标是不是 Java JVM，会跳过。

已经加载过 DeepFlow Agent 不会作为拒绝条件。因为合法的重复 attach 仍然可能再次调用 `Agent_OnAttach`。

### 第三步：HotSpot 使用 namespace helper 获取版本

只有 HotSpot 执行版本门禁，OpenJ9 等其他 JVM 不执行 Java 8u382 检查。

版本获取不读取 `release` 文件，也不调用 Agent/Host 环境中的 `java`。生产代码使用
`jvm_symbol_collect.c` 中的 helper/runner 流程；`agent/src/ebpf/tools/java_mnt_ns_version.c`
提供同一 namespace 路径选择的独立验证工具：

1. 在切换 namespace 前，从 `/proc/<pid>/exe` 获取目标 JVM 的真实可执行文件；
2. 从 `/proc/<pid>/environ` 读取目标 Java 的 `LD_LIBRARY_PATH`、`JAVA_HOME`、`PATH`、
   `HOME` 和 `LANG` 等必要环境变量。该文件使用 NUL 字符分隔，不能按普通文本行读取；
3. 根据目标 Java 的 `bin/java` 路径补充对应架构的 `lib/<arch>/jli` 目录，确保启动器可以
   找到 `libjli.so`；
4. 创建独立的版本探测 helper。helper 调用 `setns()` 进入目标 PID/mount namespace；
   `setns(CLONE_NEWPID)` 不改变 helper 自身的 PID，只影响 helper 后续创建的子进程；
5. helper 再创建 runner，runner 使用 `execve()` 直接执行目标 `/proc/<pid>/exe` 的绝对路径，
   参数为 Java 8 兼容的 `-version`，并通过管道把标准输出和标准错误传回父进程；
6. Agent 父进程以非阻塞方式读取版本输出，同时用单调时钟实施 5 秒超时。超时后杀掉
   helper 所在的进程组并回收 helper，避免 Java runner 残留；
7. helper 执行完成后立即退出，不需要调用 `df_exit_ns()`。目标 namespace 只存在于 helper
   和 runner 中，Agent 父进程及其后续子进程从未进入目标 namespace，因此不需要恢复或
   额外验证父进程 namespace。

父进程的等待是一个循环，不是一次阻塞等待：

```text
while (helper 尚未退出 || 版本输出管道尚未关闭) {
    非阻塞读取 Java -version 输出；
    waitpid(helper_pid, ..., WNOHANG) 检查 helper 是否退出；
    检查单调时钟是否超过 5 秒 deadline；
    poll(版本输出管道读端，最多等待 100ms)；
}
```

这里的管道由 `pipe()` 创建：`pipe_fds[0]` 是父进程读取端，`pipe_fds[1]` 是 runner
写入端。runner 将自己的标准输出和标准错误通过 `dup2()` 指向写入端，因此父进程的
`poll()` 等待的是 `pipe_fds[0]` 是否有版本数据、EOF 或错误，不是等待 Java 目标进程。
`waitpid(helper_pid, ..., WNOHANG)` 单独检查第一层 fork 创建的 helper；helper 内部会阻塞
等待第二层 fork 创建的 runner，所以 helper 退出通常表示 runner 和 `-version` 已经结束。
`poll()` 每次最多等待 100ms，醒来后重新检查 helper 和总 deadline，避免无输出时忙等，也
避免任何单次等待绕过 5 秒上限。

如果当前时间达到 deadline，父进程使用 `kill(-helper_pid, SIGKILL)` 终止 helper 进程组，
再 `waitpid()` 回收 helper。进程组中包括 helper 和 runner，但不包括正在运行的目标 Java
业务进程。超时、管道错误、helper 非正常退出或版本输出无法解析时，预检统一失败并跳过
attach。

这套流程不使用 `nsenter`，不使用 `chroot`，也不需要宿主机安装额外的 namespace 工具。
版本 helper 结束后，目标 PID/mount namespace 不会留给 Agent 后续子进程；namespace
切换发生在独立 helper 中，helper 退出后由内核回收其 namespace 状态。
测试表明，即使 Host 和 POD 存在相同绝对路径但版本不同的 Java，执行结果仍来自目标 POD
的 Java，而不是 Host Java。Java 8 使用 `-version`，不能使用 `--version`。

这里的 `-version` 不是向正在运行的目标 JVM 发送命令，也不会对目标 JVM 执行 attach。
它是在目标 PID/mount namespace 中启动一个短生命周期的独立 Java 子进程，用来确认目标
Java 启动器能够正常启动并报告版本。目标 JVM 本身不会因为这一步加载 Agent 或开启 JVMTI
回调。版本 helper 和 runner 结束后，父进程回收 helper。

这一步存在以下现实限制：

- 目标容器没有进入目标 PID/mount namespace 的权限时，版本命令无法启动；
- `/proc/<pid>/exe`、`/proc/<pid>/environ` 或 namespace 文件不可读时，版本检查失败；
- 精简 JRE 缺少 `libjli.so`、动态链接器或必要运行库时，版本命令可能失败；
- 目标 JDK 文件在检查期间被替换时，子进程版本可能与原 JVM 已加载的库不一致；
- 启动器异常、5 秒内未退出或版本子进程未正常结束时，检查会失败；
- runner 使用目标 Java 的显式运行环境白名单，但 helper/runner 仍可能继承打开的文件描述符；
  生产代码应避免在版本探测期间持有不必要的敏感描述符。

因此，`-version` 失败不能被解释为“版本安全”，代码会保守跳过 attach。版本命令结束后
仍需重新校验 PID start time 和 `/proc/<pid>/exe`，但无法完全防止运行时文件被外部替换。

如果 `-version` 执行失败或输出中没有标准版本字符串，无法确认版本，直接保守跳过 attach。

#### Java 8 版本范围与 8u382 门禁

版本判断首先识别 Java 8 update 所处的补丁范围：

```text
update <= 351       -> 缺少 JDK-8173361，高风险
352 <= update <= 381 -> 已有第一组修复，但缺少 JDK-8305165，残余风险
update >= 382       -> 两组标准 OpenJDK 修复齐全，达到当前安全基线
```

当前 attach 策略采用完整修复门禁，只允许最后一段继续执行：

```text
HotSpot && Java 主版本 == 8 && update < 382
    -> 跳过 attach
```

例如：

- `1.8.0_342`：属于缺少首个修复的高风险段，跳过 attach；
- `1.8.0_352`：属于部分修复段，当前仍跳过 attach；
- `1.8.0_381`：属于部分修复段，当前仍跳过 attach；
- `1.8.0_382`：通过版本门禁；
- `1.8.0_412`：通过版本门禁。

注意：`8u352–8u381` 不是“已确认必然崩溃”的范围，而是“补丁不完整、不能仅凭版本号确认安全”的范围。若目标厂商明确证明这些构建已额外回移 JDK-8305165 或等价补丁，才能设计例外放行；当前版本命令输出不会携带补丁提交列表，代码无法仅靠 `JAVA_VERSION` 自动识别这一点。

不再获取或判断 `FULL_VERSION`、`JVM_VERSION`，也不再获取和校验厂商白名单。

### 第四步：OpenJ9 等非 HotSpot JVM

如果识别到的是 OpenJ9：

- 不执行 HotSpot 专用的 Java 版本获取和门禁；
- 不执行 Java 8u382 门禁；
- 只继续执行通用进程、Attach 和 PID 竞态检查。

通用检查通过后，OpenJ9 可以继续原有 attach 流程。

### 第五步：检查 Attach 是否被禁用

代码读取目标进程的 `cmdline` 和 `environ`，查找：

```text
-XX:+DisableAttachMechanism
```

如果找到，说明 JVM 明确禁止 attach，代码会跳过，不再执行注入。

如果 `cmdline` 或 `environ` 无法读取，也无法确认 Attach 能力，代码同样会保守跳过，
避免把“检查失败”误判为“没有禁用参数”。`environ` 只保存进程启动时的环境，因此
仍然需要同时检查 `cmdline`。

检查使用完整的 JVM option 边界：

- `cmdline` 按 NUL 分隔的 argv 项匹配，只有完整参数等于
  `-XX:+DisableAttachMechanism` 时才命中；例如业务参数
  `--note=-XX:+DisableAttachMechanism` 不会命中；
- `environ` 只解析标准 JVM 选项环境变量 `JAVA_TOOL_OPTIONS`、`_JAVA_OPTIONS`
  和 `JDK_JAVA_OPTIONS`，并按空白分隔的完整 token 匹配；无关环境变量中的普通文本不会命中。

### 第六步：再次确认 PID 没有被复用

检查结束前，代码重新读取：

- PID start time；
- `/proc/<pid>/exe`。

如果启动时间或可执行文件发生变化，说明进程可能已经退出并被其他进程复用了，本次检查结果作废，不执行 attach。

## 4. 最终判断

| 情况 | 处理方式 |
| --- | --- |
| 进程退出或是僵尸进程 | 跳过 attach |
| 找不到 JVM 核心库 | 跳过 attach |
| HotSpot，`-version` 执行失败或无法解析 | 跳过 attach |
| HotSpot，`8u0–8u351` | 缺少 JDK-8173361，跳过 attach |
| HotSpot，`8u352–8u381` | 补丁不完整，当前跳过 attach |
| HotSpot，版本达到 8u382 或更高 | 通过版本门禁，继续通用检查 |
| OpenJ9 等非 HotSpot JVM | 不做版本门禁，继续通用检查 |
| `DisableAttachMechanism` 已启用 | 跳过 attach |
| `cmdline` 或 `environ` 无法读取 | 跳过 attach |
| PID 在检查期间发生变化 | 跳过 attach |
| 所有检查通过 | 才执行 attach |

跳过时会输出统一日志，例如：

对于低于 8u382 的 HotSpot Java 8，`reason` 统一说明：Java 程序缺失
`JDK-8173361` 和 `JDK-8305165` 修复，存在崩溃风险，为安全起见不执行 attach。

```text
JAVA_ATTACH_SKIP pid=1234 reason=hotspot_java8_missing_JDK-8173361_and_JDK-8305165_crash_risk jvm=1.8.0_212 required=8u382+
```

## 5. 本机验证结果

测试均在本机隔离环境完成：

### 5.1 JVM 缺陷复现测试

| 测试项 | 结果 |
|---|---|
| 8u342 无 Agent 基线 | PASS，30 秒正常退出 |
| 8u342 + Honest Profiler，类加载/卸载压力 | **SIGSEGV**，约 26 秒 |
| 8u342 + DeepFlow，类加载/卸载压力 | **SIGSEGV**，约 16–17 秒 |
| 8u342 + DeepFlow，重复 attach 60 次 | PASS，60/60 成功 |
| 8u342 + DeepFlow，socket 背压 | PASS，300 秒正常退出 |
| 8u382 + Honest Profiler，同等压力 300 秒 | PASS，无 SIGSEGV |
| 8u382 + DeepFlow，同等压力 300 秒 | PASS，无 SIGSEGV |

### 5.2 Attach 预检测试

| 测试项 | 结果 |
|---|---|
| C 代码编译 | PASS |
| `git diff --check` | PASS |
| HotSpot 8u342 版本识别 | PASS，跳过 attach |
| HotSpot 8u382 版本识别 | PASS，通过版本门禁 |
| HotSpot 8u412 版本识别 | PASS，允许继续检查 |
| POD 中 HotSpot 8u212 | PASS，正确跳过 attach |
| Host 与目标同 namespace | PASS，不切换 namespace |
| Host 与目标跨 namespace | PASS，`java_mnt_ns_version` 使用目标 PID/mount namespace |
| Host 与 POD 存在相同 Java 绝对路径 | PASS，仍获取 POD Java 的真实版本 |
| 极简容器缺少目标侧 shell/env/timeout | PASS，不依赖 `nsenter`、`chroot` 或目标侧辅助命令 |
| `DisableAttachMechanism` 参数 | PASS，正确跳过 |
| 业务参数仅包含 `-XX:+DisableAttachMechanism` 文本 | PASS，不误判为禁用 attach |
| 无关环境变量仅包含该文本 | PASS，不误判为禁用 attach |
| `JAVA_TOOL_OPTIONS` 包含完整禁用参数 | PASS，正确跳过 |
| PID 被复用或 exe 变化 | PASS，正确跳过 |

其中，`8u352` 和 `8u381` 的可执行包当前尚未取得，因此只完成版本范围推导，未做二进制压力复现。

以上远端测试只执行版本检查和 `java_attach_preflight()`，没有执行 jattach，也没有修改目标 Java 进程。
测试机当前沙箱不具备完整 JVM attach 条件，因此 8u382 在通过预检后，实际 jattach 可能因
attach socket 或 namespace 权限失败。这属于测试环境限制，不是 JVM 版本门禁拒绝。

## 6. 代码位置

- 公共预检逻辑：`agent/src/ebpf/user/profile/java/jvm_symbol_collect.c` 中的 `java_attach_preflight()`；
- Java 版本获取实现：`agent/src/ebpf/user/profile/java/jvm_symbol_collect.c`；通过独立
  helper、`setns(PID namespace)`、`setns(mount namespace)` 和 `execve(<目标绝对路径>,
  {<目标路径>, "-version"})` 获取目标 Java 版本，不依赖 `nsenter` 或 `chroot`；
- 独立验证工具：`agent/src/ebpf/tools/java_mnt_ns_version.c`；用于验证目标 namespace
  中的 Java 路径、动态库环境和 namespace 恢复行为；
- 预检数据结构和返回值：`agent/src/ebpf/user/profile/java/jvm_symbol_collect.h`；
- Agent 采集结果对“主动跳过”的处理：`agent/src/ebpf/user/profile/java/collect_symbol_files.c`。
