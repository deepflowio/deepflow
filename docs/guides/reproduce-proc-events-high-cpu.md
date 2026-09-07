# `proc-events` 高 CPU 复现指南

适用版本：DeepFlow Agent `v6.6.5811`

## 1. 目的

本文用于在测试环境复现并验证 DeepFlow Agent 的以下故障机制：

```text
进程符号缓存仍被引用（p->use > 0）
        -> 进程退出或发生 exec
        -> proc-events 回收旧缓存
        -> free_symbolizer_cache_kvp() 等待 p->use 归零
        -> 忙等循环占满一个 CPU 核心
```

文档还包含一个可选用例，用于复现 Java 符号刷新请求与完成通知错配的竞态。

> **警告：** 本文的故障注入会故意阻塞 Agent 工作线程，只能在隔离的测试环境执行。
> 禁止将包含故障注入代码的二进制部署到客户或生产环境。

## 2. 相关线程

```text
sk-reader
  -> 从 eBPF perf buffer 接收进程 exec/exit 事件
  -> 将事件写入 proc_event_ring

proc-events
  -> 消费 proc_event_ring
  -> 回收旧进程缓存时调用 free_symbolizer_cache_kvp()

oncpu-reader
  -> 解析 profiling 栈符号
  -> 临时持有 symbolizer_proc_info::use

java_update
  -> 消费 java_syms_update_tasks_head
  -> Java 更新任务完成前一直持有 symbolizer_proc_info::use

Java collector worker
  -> 执行 worker_thread() 和 ipc_receiver_main()
  -> 更新 Java perf-map 文件并通知请求线程
```

Java collector worker 可能继承 `java_update` 线程名。判断线程身份时应查看用户态调用栈，
不能只看线程名。

## 3. 前置条件

- 独立的 Linux 测试主机或虚拟机。
- 保留调试符号的 DeepFlow Agent 测试版本。
- 已启用 OnCPU profiling。
- 一个被 profiler 选中的、长时间运行的 Java 测试进程。
- 已安装 `perf`、`gdb` 或 `pstack`，可选安装 `bpftrace`。
- 具备重新编译和重启测试 Agent 的权限。

Agent 的编译和部署方法参见 [How to build](How-to-build.md)。

## 4. 复现 `proc-events` 持续高 CPU

### 4.1 注入一个有界延迟

编辑 `agent/src/ebpf/user/profile/java/collect_symbol_files.c`。在
`java_syms_update_main()` 中，将临时延迟放在 `collect_java_symbols()` 之后、
任务释放 `p->use` 之前：

```c
collect_java_symbols(p->pid, &ret, p->gen_java_syms_file_err);

/* TEST ONLY: keep the symbolizer proc-info reference for 60 seconds. */
ebpf_warning("REPRO: hold p->use, pid=%d use=%lu\n",
	     p->pid, AO_GET(&p->use));
sleep(60);
```

保留原有的引用释放代码：

```c
AO_DEC(&p->use);
```

推荐使用有限的 60 秒延迟，不要注入永久等待。这样可以验证：引用释放后，
`proc-events` 的 CPU 是否随即恢复。

### 4.2 编译并启动测试 Agent

编译包含上述故障注入的 Agent，在测试主机上启动，并确认 OnCPU profiler 正在采集
目标 Java 进程。

记录 Agent PID：

```bash
agent_pid=$(pgrep -xo deepflow-agent)
echo "$agent_pid"
```

### 4.3 触发 Java 符号更新

运行持续执行 JIT 编译代码的 Java 测试负载。等待 unknown Java frame 触发符号更新任务，
并确认日志出现：

```text
REPRO: hold p->use, pid=<target-pid> use=<value>
```

记录日志中的 `<target-pid>`。

如果负载不能自然触发更新，可使用反复创建短生命周期 ClassLoader 并触发 GC 的测试程序，
或者在测试配置中缩短 Java 符号刷新延迟。

### 4.4 在延迟期间退出目标进程

确认 Agent 已进入 60 秒延迟后，正常终止目标 Java 测试进程：

```bash
kill -TERM <target-pid>
```

禁止对生产进程执行该操作。

退出事件由 `sk-reader` 接收并写入 `proc_event_ring`，随后由 `proc-events` 消费。
缓存回收会释放自身引用，但故障注入的 Java 更新任务仍持有一个引用。

### 4.5 观察结果

查看线程 CPU：

```bash
pidstat -t -p "$agent_pid" 1 20
```

延迟期间的预期结果：

```text
线程名：proc-events
CPU：   接近占满一个核心
```

抓取用户态线程栈：

```bash
sudo gdb -q -batch -p "$agent_pid" \
  -ex 'set pagination off' \
  -ex 'thread apply all bt full' \
  -ex detach \
  > /tmp/deepflow-repro-stacks.txt 2>&1
```

`proc-events` 调用栈应包含：

```text
process_events_handle_main
exec_proc_info_cache_update
free_symbolizer_cache_kvp
```

OnCPU 火焰图中，`proc-events` 的大部分样本应落在
`free_symbolizer_cache_kvp()`。

60 秒后，Java 更新线程执行 `AO_DEC(&p->use)`。此时
`free_symbolizer_cache_kvp()` 应结束等待，`proc-events` CPU 恢复正常。
这可以证明高 CPU 来自未释放引用，而不是进程事件入队本身。

## 5. 进程抖动对照测试

在测试环境运行有界的短命进程负载：

```bash
seq 1 5000 | xargs -P 32 -I {} /bin/true
```

如果没有故障注入或引用泄漏，`proc-events` CPU 可以短暂升高，但负载结束后必须恢复。
如果事件速率恢复正常后仍持续占满一个核心，应立即抓取线程栈；此时很可能存在未释放的
进程缓存引用。

## 6. 可选：复现刷新与通知错配

该用例验证以下竞态：collector 检查 `need_refresh` 后，新请求才到达；collector 随后却把
这个新请求清除并通知为已完成。

### 6.1 扩大竞态窗口

在 `ipc_receiver_main()` 中临时拆分原有表达式，并在刷新检查与通知之间增加延迟：

```c
int ret = update_java_perf_map_file(args, NULL);

/* TEST ONLY: allow a request to arrive after the refresh check. */
ebpf_warning("REPRO: refresh check completed, waiting before notify\n");
usleep(5 * 1000 * 1000);

refresh_symbol_file_and_notify(args, ret);
```

在实际刷新分支和通知位置增加临时日志：

```text
REPRO_REFRESH_EXECUTED pid=<pid>
REPRO_REFRESH_NOTIFIED pid=<pid> status=<status>
```

### 6.2 触发竞态

1. 启动 Java collector，等待 `need_refresh` 变为 false。
2. 等待日志出现 `REPRO: refresh check completed`。
3. 在五秒延迟期间触发一次 unknown-symbol 更新请求。
4. 对比请求线程和 collector 的日志。

修复前的预期结果：

```text
collector 检查到 need_refresh == false
  -> 请求线程设置 need_refresh = true 并开始等待
  -> collector 没有执行该请求对应的刷新分支
  -> collector 仍然清除 need_refresh 并通知成功
```

如果一条 `REPRO_REFRESH_NOTIFIED` 没有对应的 `REPRO_REFRESH_EXECUTED`，说明竞态复现成功。

使用请求快照修复后的预期结果：

```text
collector 不会通知在快照之后到达的请求
  -> 请求保持 pending
  -> 下一轮 collector 执行刷新
  -> 刷新结束后再通知请求线程
```

## 7. 需要保留的证据

修复前后均应保留：

- Agent 版本 `v6.6.5811`、准确 commit 和可执行文件 Build ID。
- 复现前后至少各五分钟的 Agent 日志。
- `/tmp/deepflow-repro-stacks.txt`。
- 原始 `perf.data`，不能只保留火焰图图片。
- `pidstat` 的线程 CPU 输出。
- 目标 PID、进程名、`p->use`、任务入队时间、出队时间和刷新完成时间。

推荐按以下顺序关联日志：

```text
Java 符号任务入队
  -> Java 符号任务出队
  -> 收到进程退出事件
  -> proc-events 开始等待 p->use
  -> Java 刷新完成或超时
  -> AO_DEC(&p->use)
  -> proc-events CPU 恢复正常
```

## 8. 清理

1. 删除所有测试延迟和 `REPRO` 日志。
2. 重新编译不包含故障注入的 Agent。
3. 重启测试 Agent。
4. 确认可执行文件和日志中不再包含 `REPRO` 字符串。
5. 再次运行进程抖动对照测试，确认负载结束后 CPU 可以恢复。
