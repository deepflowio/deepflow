# Proc Cache 内存保护设计

## 1. 文档状态

本文描述 DeepFlow Agent 用户态 Proc Cache 的容量限制、超限降级、延迟回收、配置、日志和
可观测性设计。

本文是设计文档，不代表相关代码已经全部实现。实施时应以本文列出的约束和验收条件为准。

## 2. 背景

DeepFlow Agent 使用 `symbolizer_proc_info` 保存进程启动时间、进程名、容器信息、线程名和
用户态符号缓存等信息，并使用以 PID 为 key 的 bihash 查找这些对象。

进程退出或 exec 后，对象会先从 hash 中删除。如果仍有查询或 Java symbol task 持有引用，
对象不能立即释放，只能进入 `retired_proc_caches`，等待引用计数 `use` 归零后再回收。

延迟回收解决了删除线程等待引用归零时长期自旋的问题，但同时引入了新的容量风险：

1. 大量进程快速创建和退出时，Proc Cache 对象可能快速创建。
2. 如果某类引用长期不归还，`retired_proc_caches` 会持续积累。
3. bihash 的内存参数不是 Proc Cache 对象数量限制，不能阻止对象无限创建。
4. Proc Cache 还可能持有 BCC symbol cache，其真实内存远大于结构体本身。

因此需要为所有已经创建、但尚未真正释放的 Proc Cache 对象设置统一上限。

## 3. 当前数据结构与容量

### 3.1 Hash 的 key 和 value

Proc Cache hash 使用 `_8_8` bihash：

```c
struct symbolizer_cache_kvp {
	struct {
		u64 pid;
	} k;

	struct {
		uword proc_info_p;
	} v;
};
```

含义如下：

```text
key   = PID，8 bytes
value = struct symbolizer_proc_info *，8 bytes
```

每个 hash KV 的原始大小为 16 bytes。同一个 PID 在同一时刻只能对应一个 Proc Cache。
`stime` 不属于 hash key，PID 复用依靠 exec/exit 事件和进程启动时间校验处理。

### 3.2 Hash 的初始容量不是最大容量

当前配置为：

```c
#define SYMBOLIZER_CACHES_HASH_BUCKETS_NUM 8192
#define BIHASH_KVP_PER_PAGE                7
#define SYMBOLIZER_CACHES_HASH_MEM_SZ      (1ULL << 31) /* 2 GiB */
```

初始槽位数为：

```text
8192 buckets * 7 slots = 57,344 slots
```

`57,344` 不是最大进程数。某个 bucket 用完初始槽位后会动态扩容，扩容最终受 2 GiB
bihash arena 限制。由于 hash 冲突、扩容、对齐、临时副本和 freelist 碎片，无法从 2 GiB
得到稳定且可依赖的最大条目数。

另外，2 GiB 只用于 bihash 自己的 bucket/KV 存储，`symbolizer_proc_info`、线程名 vector 和
BCC symbol cache 均在这个 arena 之外分配。因此不能把 2 GiB bihash arena 当作 Proc Cache
的内存保护。

### 3.3 单个 Proc Cache 的基础大小

当前 x86_64 编译结果为：

```text
sizeof(struct symbolizer_proc_info) = 240 bytes
```

这是版本和架构相关的值，实施后应在目标架构构建中再次核对。实际内存还包括：

- `thread_names` 动态 vector；
- BCC symbol cache；
- 分配器元数据和对齐；
- bihash 扩容空间；
- 关联但可能共享的 mount cache 数据。

### 3.4 已有活动数量统计

`syms_cache_hash.hash_elems_count` 表示当前 hash 中的活动 Proc Cache 数量。成功加入 hash 后
加一，成功删除后减一。

该值不包括：

- 已经从 hash 删除、正在通过 proc event ring 转交的对象；
- `retired_proc_caches` 中等待释放的对象；
- 已经预留容量、但尚未完成 hash 插入的对象。

因此它可以作为 `active_count`，但不能作为总内存保护计数。

## 4. 设计目标

本设计需要满足以下目标：

1. 所有尚未真正释放的 `symbolizer_proc_info` 数量存在硬上限。
2. 进程疯狂启停或引用长期不归还时，内存不能无限增长。
3. 达到上限后，现有对象的查询、删除和回收继续工作。
4. 不强制释放仍有引用的对象，不引入 UAF。
5. 不重新引入等待引用归零的阻塞或忙等。
6. 正常 hash 查询热路径不增加全局锁或新的全局原子竞争。
7. 提供配置、日志、计数器和控制命令，能够解释容量为何被占满。
8. 配置可以调整，但必须有安全的默认值和取值范围。

## 5. 非目标

第一阶段不解决以下问题：

1. 不精确统计 BCC symbol cache 内部的全部内存。
2. 不根据 RSS 自动驱逐任意 Proc Cache。
3. 不实现 active Proc Cache 的 LRU 淘汰。
4. 不在达到上限时杀死、暂停或影响目标进程。
5. 不保证所有新进程都有符号解析结果；超限时允许观测能力降级。

## 6. 对象状态与统一计数

### 6.1 状态定义

一个 Proc Cache 从容量角度存在以下状态：

```text
RESERVED    已预留总量名额，正在分配或初始化
ACTIVE      已加入 proc info hash
IN_FLIGHT   已从 hash 删除，正在 proc event ring 中转
RETIRED     已离开 hash，但仍有引用，等待回收
FREED       已执行 free_proc_cache()，不再占用名额
```

典型生命周期：

```text
新进程/exec
    |
    v
RESERVED ---- 初始化失败 -------------------------------> FREED
    |
    v
ACTIVE ------ 退出/exec，从 hash 删除 -----------------> IN_FLIGHT
                                                        |
                                      +-----------------+-----------------+
                                      |                                   |
                                      v                                   v
                                  use == 0                            use > 0
                                      |                                   |
                                      v                                   v
                                    FREED                              RETIRED
                                                                          |
                                                                    use == 0
                                                                          |
                                                                          v
                                                                        FREED
```

### 6.2 总量定义

新增全局计数：

```text
proc_cache_total_count
```

其逻辑含义为：

```text
total_count = RESERVED + ACTIVE + IN_FLIGHT + RETIRED
```

必须始终满足：

```text
proc_cache_total_count <= proc_cache_total_limit
```

对象从 ACTIVE 转移到 IN_FLIGHT，再转移到 RETIRED，只改变状态，不改变 `total_count`。
只有对象最终执行 `free_proc_cache()` 后，`total_count` 才减一。

### 6.3 为什么不能只限制 active

如果只限制 hash 中的 active 对象，可以出现：

```text
active_count  = 65,536
retired_count = 持续增长
```

进程退出后会离开 hash，空出来的 active 名额又会被新进程使用。如果旧对象由于引用泄漏停留
在 retired list，总内存仍会持续增长。

因此必须限制 active、in-flight 和 retired 的总和，而不是仅限制 hash 条目数。

### 6.4 为什么 retired 不能在插入时拒绝

对象进入 retired list 时仍然有外部引用，不能因为 retired 数量达到阈值就拒绝管理该对象：

- 强制释放会导致 UAF；
- 丢弃对象指针会造成永久泄漏且失去诊断入口；
- 同步等待 `use == 0` 会重新引入死等或高 CPU 自旋。

正确做法是始终允许已有对象进入 retired list，同时通过创建入口的总量限制阻止新对象继续
增加。这样 retired 最坏可以占满全部名额，但总对象数量不会突破硬上限。

## 7. 配置设计

### 7.1 配置项

建议增加一个配置项，不同时暴露 active、retired 和 total 三个容易混淆的限制：

```yaml
inputs:
  ebpf:
    tunning:
      proc_cache_max_entries: 65536
```

语义为：

> DeepFlow Agent 允许同时存在的、尚未真正释放的 `symbolizer_proc_info` 最大数量，包括
> active hash、proc event ring 中转、初始化中和 retired list 中的对象。

### 7.2 类型、单位和范围

```text
类型：    u32
单位：    entries
最小值：  1,024
默认值：  65,536
最大值：  262,144
```

建议定义：

```c
#define PROC_CACHE_LIMIT_MIN      1024U
#define PROC_CACHE_LIMIT_DEFAULT  65536U
#define PROC_CACHE_LIMIT_MAX      262144U
```

配置值不要求是 2 的幂，因为它限制的是对象数量，不是 bihash bucket 数量。

### 7.3 配置校验

配置行为应明确：

1. 未配置时使用默认值 `65,536`。
2. `0` 不表示无限制；`0` 属于非法值。
3. 小于 `1,024` 或大于 `262,144` 时给出包含合法范围的明确错误。
4. 不对非法值静默截断。
5. 启动阶段遇到非法值时，按照 Agent 统一的配置错误策略处理。
6. 热更新遇到非法值时拒绝更新，继续使用旧值。

### 7.4 热更新

如果该配置支持热更新：

- 调大限制：新值立即生效；
- 调小限制且 `total_count <= new_limit`：新值立即生效；
- 调小限制且 `total_count > new_limit`：不强制释放现有对象，新值仍可生效，但停止新建，
  直到 `total_count` 自然下降到新限制以下。

配置值使用原子 load/store 访问。更新配置不需要锁住 proc info hash。

### 7.5 配置文件中的完整说明

配置模板和中英文配置文档必须明确写出：

```yaml
inputs:
  ebpf:
    tunning:
      # Maximum number of allocated process-cache objects.
      #
      # Includes active proc-info hash entries, objects being transferred
      # through the proc-event ring, objects under initialization, and objects
      # waiting in the retired reclaim list.
      #
      # Range: [1024, 262144]
      # Default: 65536
      # Unit: entries
      #
      # On x86_64, the current base size of one proc-info object is 240 bytes.
      # At the default limit, all proc-info structures occupy about 15 MiB.
      # If all entries are active, raw hash KVs add about 1 MiB.
      #
      # Actual memory usage can be significantly higher. The estimate excludes
      # thread-name vectors, BCC symbol caches, allocator overhead, hash growth,
      # fragmentation, and shared mount-cache data.
      #
      # When the limit is reached, creation of new proc-info objects is skipped.
      # Existing entries continue to be queried, deleted, and reclaimed.
      proc_cache_max_entries: 65536
```

## 8. 内存模型

### 8.1 可估算的基础内存

对于当前 x86_64 构建：

```text
每个 symbolizer_proc_info = 240 bytes
每个活动 hash KV          = 16 bytes
```

配置满额时的基础内存如下：

| 配置值 | Proc Cache 结构体 | 活动 hash KV 原始大小 | 两者合计约值 |
| ---: | ---: | ---: | ---: |
| 1,024 | 0.23 MiB | 0.02 MiB | 0.25 MiB |
| 65,536 | 15 MiB | 1 MiB | 16 MiB |
| 262,144 | 60 MiB | 4 MiB | 64 MiB |

表中的 hash KV 列假设所有对象均为 ACTIVE。RETIRED 对象已经不占用活动 hash KV，但仍占用
Proc Cache 结构体及其动态资源。

### 8.2 Hash 固定和扩展开销

初始 bucket/KV 布局约占 960 KiB，并通常按 2 MiB 粒度映射。bucket 冲突时还会发生动态扩容，
因此实际 hash 内存不能简单按 `active_count * 16` 精确计算。

### 8.3 未纳入基础估算的内存

以下内存必须在配置说明和命令输出中明确标注为“未计入”或“无法精确统计”：

- BCC symbol cache 内部对象；
- `thread_names` vector 的容量冗余；
- libc/clib 分配器元数据；
- bihash 扩容、working copy 和碎片；
- 共享 mount cache；
- Java symbol 生成任务和文件相关资源。

因此 `proc_cache_max_entries` 是对象数量安全阀，不是 Agent 总 RSS 的精确内存预算。如果后续
需要严格限制符号内存，应为 BCC symbol cache 单独设计数量或内存预算。

## 9. 容量预留与释放

### 9.1 创建前原子预留

创建对象前必须使用 compare-and-swap 原子预留名额，不能采用“先读取、再加一”的两步操作，
否则并发创建可能突破上限。

伪代码：

```c
bool try_reserve_proc_cache_slot(void)
{
	u64 count = atomic_load(&proc_cache_total_count);

	for (;;) {
		u64 limit = atomic_load(&proc_cache_total_limit);

		if (count >= limit)
			return false;

		if (atomic_compare_exchange(&proc_cache_total_count,
					    &count, count + 1))
			return true;
	}
}
```

该操作仅出现在对象创建路径，不进入正常 hash 查询热路径。

### 9.2 所有创建入口统一执行预留

必须覆盖所有 `symbolizer_proc_info` 分配入口，至少包括：

1. Agent 启动时扫描 `/proc` 创建初始 Proc Cache；
2. proc-events 消费 exec 事件时创建新 Proc Cache；
3. 后续新增的任何直接创建入口。

建议封装统一的对象分配接口，避免未来新增入口遗漏容量预留。

### 9.3 失败路径归还名额

预留成功后，下列任意步骤失败都必须归还名额：

- 结构体内存分配失败；
- `config_symbolizer_proc_info()` 失败；
- hash 插入失败；
- 发现 PID 已存在且本次对象未被采用；
- 初始化过程中的其他错误。

每个预留名额必须满足“恰好释放一次”，既不能遗漏，也不能重复减少。

### 9.4 真正释放时减少总量

状态迁移不减少总量：

```text
ACTIVE -> IN_FLIGHT -> RETIRED
```

只有资源已经真正释放后才能减少：

```text
free_proc_cache(p) 完成
    -> proc_cache_total_count--
```

如果在开始释放前就减少，另一个线程可能立即创建新对象，造成释放旧资源和分配新资源的内存
峰值叠加。

## 10. 达到上限后的行为

### 10.1 总体策略

达到上限后只拒绝新对象创建，所有能够降低内存的操作继续执行：

```text
total_count >= total_limit
        |
        +-- 新 Proc Cache 创建：拒绝
        +-- 现有 hash 查询：继续
        +-- 进程退出/exec 删除：继续
        +-- proc event ring 消费：继续
        +-- retired 扫描与回收：继续
        +-- total_count 降低：自动恢复创建
```

### 10.2 不得阻断退出和回收路径

容量判断只能放在新对象的分配入口，不能阻断：

- 从 hash 删除旧对象；
- 把仍有引用的旧对象加入 retired list；
- 扫描 retired list；
- 对 `use == 0` 的对象执行最终释放。

否则容量达到上限后将无法自行恢复。

### 10.3 exec 路径

同一 PID exec 时，应先处理旧 Proc Cache 的所有权：

1. 旧对象从 hash 删除；
2. 旧对象进入 IN_FLIGHT；
3. 旧对象根据 `use` 被立即释放或加入 retired list；
4. 再尝试为新进程镜像预留和创建 Proc Cache。

如果总量仍达到限制，新对象创建失败，但旧对象必须保持可回收状态。

### 10.4 降级影响

未能创建 Proc Cache 的目标进程继续正常运行，Agent 也继续采集其他数据。可能出现的观测降级
包括：

- 进程名或容器信息缺失；
- PID 启动时间无法从缓存获取；
- 用户态符号解析结果缺失；
- 部分持续剖析数据只能展示地址或 unknown。

容量保护优先保证 Agent 不因无界内存增长而被 OOM。

## 11. Retired List 并发保护

### 11.1 全局锁职责

`retired_proc_caches_lock` 只保护以下数据和操作：

- retired 链表头；
- `retired_next` 链接关系；
- 首次加入时间 `retired_at_ns`；
- `retired_count`；
- 从 retired list 摘除对象。

该锁不参与正常 proc info hash 查询。

### 11.2 加入时间

对象第一次实际链接到 retired list 时设置：

```c
p->retired_at_ns = gettime(CLOCK_MONOTONIC, TIME_TYPE_NAN);
```

要求：

1. 在 retired list 插入临界区内设置；
2. 每个对象只设置一次；
3. 后续扫描不能刷新；
4. 等待时间使用 `CLOCK_MONOTONIC` 计算，不受系统实时时钟回拨影响。

等待时间：

```text
wait_ns = monotonic_now_ns - retired_at_ns
```

### 11.3 回收锁范围

reaper 应在锁内摘除所有 `use == 0` 的对象，放到局部回收链表；释放 BCC symbol cache 等耗时
操作必须在解锁后进行：

```text
lock retired list
    -> 找到 use == 0 的对象
    -> 从全局链表摘除
    -> retired_count--
unlock retired list
    -> free_proc_cache()
    -> total_count--
```

这样控制命令和新 retired 对象插入不会被耗时释放长期阻塞。

## 12. 日志设计

### 12.1 限频策略

容量达到上限时不能为每一个失败进程打印日志，否则进程风暴会转化为日志和 CPU 风暴。

建议行为：

```text
第一次达到上限      立即打印 WARNING
持续处于超限状态    每 2 小时最多重复一次 WARNING
恢复到限制以下      立即打印一次 INFO
恢复后再次达到上限  立即打印 WARNING
```

时间间隔：

```c
#define PROC_CACHE_LIMIT_WARN_INTERVAL_NS \
	(2ULL * 60 * 60 * NS_IN_SEC)
```

限频使用 `CLOCK_MONOTONIC`，不能使用可能回拨的 `CLOCK_REALTIME`。

### 12.2 日志内容

达到上限：

```text
Proc cache limit reached: total=65536 limit=65536 active=54120 retired=11320 rejected=1823
```

恢复：

```text
Proc cache capacity recovered: total=65480 limit=65536 rejected=1841
```

### 12.3 计数优先于日志

即使日志被限频，每次拒绝都应增加：

```text
proc_cache_rejected_total
```

运维人员通过计数器判断两小时内实际发生了多少次降级，而不是依赖日志行数。

## 13. 控制命令设计

建议命令：

```bash
deepflow-ebpfctl proc-cache-reclaim show --older-than 60
```

其中 `--older-than` 单位为秒，只列出 retired 时间严格超过该阈值的对象。

### 13.1 汇总信息

命令至少展示：

```text
active_count
retired_count
total_count
total_limit
usage
rejected_total
admission_paused
waiting_accounted_memory
overdue_count
overdue_accounted_memory
```

示例：

```text
Proc cache reclamation:
  active_count:               54120
  retired_count:              11320
  total_count:                65536
  total_limit:                65536
  usage:                      100.00%
  admission_paused:           yes
  rejected_total:             1823
  waiting_accounted_memory:   3.10 MiB
  older_than:                 60 s
  overdue_count:              18
  overdue_accounted_memory:   420.00 KiB
```

#### 字段的通俗解释

`Proc cache reclamation` 表示“进程缓存延迟回收状态”。它展示当前有多少 Proc Cache 正在使用、
有多少已经退出 hash 但暂时不能释放，以及容量保护是否已经触发。它不是一次手工强制回收操作。

| 字段 | 通俗解释 |
| --- | --- |
| `active_count` | 当前仍在 proc info hash 中、可以通过 PID 查询到的缓存条目数。它通常接近 Agent 当前管理的进程数，但可能包含尚未被周期清理的旧条目，因此不等同于操作系统此刻准确的存活进程数。 |
| `retired_count` | 已经从 hash 删除，但因为 `use` 仍大于 0 而暂时不能释放的缓存数量。短时间等待是正常现象；持续很久通常表示某个引用没有及时归还。 |
| `total_count` | Agent 已经创建且尚未真正释放的 Proc Cache 总数，包括 active、ring 中转、初始化中和 retired 对象。这是容量保护实际检查的数字。 |
| `total_limit` | 配置允许存在的 Proc Cache 最大总数。默认是 65,536。 |
| `usage` | Proc Cache 名额使用率，即 `total_count / total_limit`。这是“对象数量使用率”，不是 Agent 的内存或 RSS 使用率。 |
| `admission_paused` | 是否已经暂停为新进程创建 Proc Cache。`yes` 只表示新 Proc Cache 被拒绝，不表示目标进程被暂停，也不表示整个 Agent 停止采集。已有缓存仍可查询、删除和回收。 |
| `rejected_total` | Agent 启动以来，因为达到容量限制而被拒绝的 Proc Cache 创建尝试累计次数。它统计的是“尝试次数”，不一定等于不同进程的数量。 |
| `waiting_accounted_memory` | 所有 retired 对象当前能够核算的内存总量。第一阶段只统计 Proc Cache 结构体和 `thread_names` vector，不包含 BCC symbol cache 等内部内存，所以实际占用可能更大。 |
| `older_than` | 本次命令使用的等待时间筛选条件。例如 `60 s` 表示下面只关注进入 retired list 超过 60 秒的对象。它不是回收周期，也不是到期后强制释放的超时时间。 |
| `overdue_count` | retired 对象中，等待时间严格超过 `older_than` 的对象数。它是 `retired_count` 的子集。 |
| `overdue_accounted_memory` | 上述 overdue 对象能够核算的内存总量，统计范围同样不包含 BCC symbol cache 内部内存。 |

字段之间的关系为：

```text
total_count = active_count + retired_count + 初始化中/中转中的对象数

overdue_count <= retired_count <= total_count
usage = total_count / total_limit * 100%
```

不能简单使用 `active_count + retired_count` 计算总数，因为命令执行时可能还有对象已经预留容量，
正在初始化，或者已从 hash 删除但仍在 proc event ring 中等待处理。

#### 示例输出的实际含义

前面的示例可以直接理解为：

```text
Agent 最多允许同时存在 65,536 个 Proc Cache，目前名额已经全部用完。

其中：
  54,120 个仍在 hash 中提供查询；
  11,320 个已经离开 hash，正在等待引用归还后释放；
      96 个正在初始化或通过 proc event ring 中转。

由于容量已满，Agent 暂停为新进程创建 Proc Cache，累计拒绝了 1,823 次创建尝试。
这不会暂停目标进程，也不会停止现有 Proc Cache 的查询和回收。

等待释放的对象中，可核算内存为 3.10 MiB；其中 18 个已经等待超过 60 秒，
这 18 个对象可核算的内存为 420.00 KiB。实际内存还可能包含未被统计的 BCC symbol cache。
```

判断是否存在问题时，不能只看 `retired_count`。应重点联合观察：

1. `retired_count` 是否持续增长且长期不下降；
2. `overdue_count` 和最长等待时间是否持续增长；
3. `LAST_INC_REASON` 是否反复指向同一种未归还引用；
4. `usage` 是否达到 100%，并且 `rejected_total` 是否持续增加。

### 13.2 明细信息

超过等待阈值的 retired 对象展示：

```text
PID
COMM
USE
WAIT(s)
ACCOUNTED_MEMORY
SYMCACHE
LAST_INC_REASON
```

`LAST_INC_REASON` 使用已有的原因标记：

```text
UNKNOWN
HASH_QUERY
JAVA_TAST
```

该值表示最近一次重要的 `use` 增加原因，不代表每种原因当前分别持有多少引用。

### 13.3 明细数量限制

控制命令不能因为 retired list 较大而构造无限大的 socket 响应。建议最多返回 1,024 条明细，
但汇总统计仍覆盖整个 retired list。

响应增加：

```text
matched_count   满足 older-than 的总数
returned_count  实际返回的明细数
truncated       是否截断
```

默认可优先返回等待时间最长的对象；如果实现排序成本过高，第一阶段可按链表顺序返回，并在输出
中明确说明。

### 13.4 内存统计口径

第一阶段的 accounted memory 定义为：

```c
sizeof(struct symbolizer_proc_info) + vec_mem_size(p->thread_names)
```

命令必须明确提示该统计不包括：

```text
BCC symbol-cache internals
allocator overhead
hash expansion and fragmentation
shared mount-cache memory
```

## 14. 运行时指标

建议提供以下长期指标：

```text
proc_cache_active_count       当前 hash 活动项数量
proc_cache_retired_count      当前等待回收数量
proc_cache_total_count        当前尚未释放的对象总数
proc_cache_total_limit        当前配置上限
proc_cache_rejected_total     因容量限制拒绝创建的累计次数
proc_cache_reclaimed_total    从 retired list 成功回收的累计次数
proc_cache_oldest_wait_secs   当前 retired list 最长等待时间
```

如果一次读取多个计数时无法获得全局一致快照，应将它们标记为 best-effort 诊断值。硬限制只依赖
`proc_cache_total_count` 的原子预留，不依赖控制命令快照的一致性。

## 15. 并发与性能要求

### 15.1 Hash 查询热路径

正常查询仍按现有生命周期保护方式执行：

```text
进入读侧保护
    -> hash_search(pid)
    -> p->use++
退出读侧保护
    -> 使用 p
    -> p->use--
```

本设计不能在该路径增加：

- `retired_proc_caches_lock`；
- 总量预留 CAS；
- 配置锁；
- 日志判断。

### 15.2 创建和释放路径

新增的总量原子操作只发生在：

- 新对象创建前；
- 创建失败归还名额时；
- 对象最终释放后。

这些操作不是每条采集数据都会执行的热查询操作。

### 15.3 计数一致性

必须保证以下不变量：

```text
成功预留次数 - 归还/最终释放次数 = total_count
active_count <= total_count
retired_count <= total_count
total_count <= total_limit，配置主动调低造成的短暂情况除外
```

配置被主动调低到当前数量以下时，允许暂时出现：

```text
total_count > total_limit
```

但此时必须拒绝全部新建，且 `total_count` 只能下降，不能继续上升。

## 16. 异常与边界场景

### 16.1 初始 `/proc` 数量超过限制

启动扫描达到限制后，停止为剩余进程创建 Proc Cache，但完成目录扫描和 Agent 初始化。打印一条
受限警告并增加拒绝计数，不能因为单个缓存子系统达到容量而导致 Agent 启动失败。

### 16.2 PID 重复或 hash 插入冲突

如果已经预留并分配对象，但 hash 插入返回 PID 已存在或其他错误，必须销毁本次未采用的对象并
归还总量名额。

### 16.3 Proc event ring 满

ring 满不能遗失已经从 hash 删除的对象所有权。实施时必须确认删除、所有权转交和 enqueue 失败
的处理顺序，保证对象最终进入可释放路径。容量计数不能代替 ring 失败处理。

### 16.4 引用永久不归还

永久引用会使对象永久停留在 retired list，但总对象数量最多为配置上限。达到上限后新进程的
Proc Cache 创建被拒绝，通过 `WAIT(s)`、`USE` 和 `LAST_INC_REASON` 定位泄漏来源。

### 16.5 配置动态调低

不主动驱逐、不强制释放、不等待。只阻止新建，直到自然回收使总量低于新上限。

### 16.6 计数溢出和下溢

所有减一操作应在调试构建中断言计数大于零。控制命令如果观察到异常大值，应报告计数损坏，
不能把无符号下溢后的值当作真实数量。

## 17. 不采用的方案

### 17.1 依赖 bihash 的 2 GiB 上限

不采用。Proc Cache 对象和 BCC symbol cache 在 bihash arena 外分配，无法提供整体保护。

### 17.2 只限制 active hash 数量

不采用。retired list 可以在 active 名额反复复用时持续增长。

### 17.3 retired 达到上限后直接释放

不采用。仍有引用时会产生 UAF。

### 17.4 retired 达到上限后丢弃指针

不采用。会造成永久内存泄漏，并失去后续回收和诊断能力。

### 17.5 达到上限后同步等待引用归零

不采用。会重新引入死等或高 CPU 自旋，并可能阻塞所有后续 proc event。

### 17.6 active LRU 淘汰

第一阶段不采用。需要处理正在查询、Java task、PID 复用和符号缓存所有权，复杂度和风险远高于
创建入口限流。

## 18. 实施步骤

建议按以下顺序实施：

1. 增加配置字段、默认值、范围校验和中英文配置说明；
2. 增加 `proc_cache_total_limit`、`proc_cache_total_count` 和拒绝累计计数；
3. 封装容量预留、失败归还和最终释放逻辑；
4. 覆盖启动 `/proc` 扫描和 proc-events 创建入口；
5. 增加 retired 数量及最长等待时间统计；
6. 增加首次立即、持续两小时一次、恢复立即的日志状态机；
7. 扩展 `proc-cache-reclaim show` 汇总和明细截断；
8. 增加运行时指标；
9. 完成并发、异常路径和进程风暴测试。

## 19. 测试方案

### 19.1 配置测试

- 未配置时使用 `65,536`；
- `1,024` 和 `262,144` 可接受；
- `0`、`1,023` 和 `262,145` 被拒绝；
- 热更新非法值时继续使用旧值；
- 调低到当前数量以下时不释放现有对象，只暂停新建。

### 19.2 计数测试

- 创建成功后 `total_count + 1`；
- 每个初始化失败路径都恢复原计数；
- ACTIVE 转 IN_FLIGHT 和 RETIRED 时总数不变；
- `free_proc_cache()` 完成后总数减一；
- hash 插入重复不会泄漏名额；
- 并发创建时总数不超过限制。

### 19.3 超限测试

使用较小的测试限制快速达到上限，验证：

- 新建被拒绝；
- 现有 hash 查询正常；
- exit/exec 删除正常；
- retired reaper 正常；
- 释放一个对象后能够创建一个新对象；
- 目标进程和 Agent 不崩溃、不忙等。

### 19.4 引用泄漏测试

人为保持 `HASH_QUERY` 或 `JAVA_TAST` 引用，反复创建和退出进程，验证：

- retired 数量增长但总数不突破限制；
- 达到限制后进入降级；
- 控制命令显示等待时间和最后引用原因；
- 归还引用后对象被 reaper 回收并恢复容量。

### 19.5 日志测试

- 首次达到限制立即打印；
- 连续拒绝不会逐条打印；
- 持续超限每两小时最多重复一次；
- 恢复时打印一次；
- 恢复后再次超限立即打印。

### 19.6 控制命令测试

- `--older-than` 使用 CLOCK_MONOTONIC 等待时间；
- 多次查询不会刷新 `retired_at_ns`；
- 汇总覆盖全部 retired 对象；
- 明细超过 1,024 条时正确截断并显示 matched/returned；
- 命令执行期间与 reaper 并发时不发生 UAF 或链表损坏。

## 20. 验收标准

实现完成后必须满足：

1. 默认配置下，未释放 Proc Cache 总数不超过 65,536；
2. 并发创建不能突破配置上限；
3. 达到上限后不阻塞 hash 查询、删除、ring 消费和 retired 回收；
4. 不强制释放 `use > 0` 的对象；
5. 所有创建失败路径均不泄漏容量名额；
6. 配置文件明确说明范围、单位、默认值和内存口径；
7. 超限日志首次立即、持续两小时限频、恢复立即；
8. 控制命令能够展示 active、retired、total、limit、拒绝次数、等待时间和引用原因；
9. 压力测试中不存在 UAF、死等、计数下溢和无界内存增长；
10. 正常 proc info hash 查询热路径不新增全局锁。
