# UDP 多 Peer `socket_id` 与 `cap_seq` 隔离设计

**日期**：2026-10-16

**状态**：已实现

**适用范围**：DeepFlow Agent Socket Tracer 采集的 UDP syscall 数据

## 1. 背景

Socket Tracer 当前使用 `PID + FD` 查找 `socket_info_map`，一个物理 socket 对应一个
`socket_info_s.uid` 和一条 `socket_info_s.seq`。

该模型适合 TCP，但 UDP 服务端通常只创建一个 socket，并使用同一个 FD 与多个客户端通信：

```text
                    client A: 10.0.0.1:10001
                              \
server process -- UDP FD 9 ----+-- server: 10.0.0.10:53
                              /
                    client B: 10.0.0.2:10002
```

在现有模型中，A 和 B 的数据都会携带同一个物理 `socket_id`，并共享一条 `cap_seq`。
用户态的 eBPF Flow ID 主要由输出事件中的 `socket_id` 生成，因此不同五元组可能进入同一个
Flow；对于没有 request ID 的 UDP 协议，后续还可能出现日志端点归属错误、请求与响应跨 peer
合并等问题。

## 2. 设计原则

本方案只改写发送给用户态的事件元数据，不改变 Socket Tracer 的原有内部处理逻辑。

| 项目 | 处理方式 |
| --- | --- |
| `socket_info_map` 的 Key | 仍为 `PID + FD` |
| `socket_info_s.uid` | 仍表示物理 socket ID |
| `socket_info_s.seq` | 保持原有物理 socket 序号逻辑 |
| 协议识别 | 不修改 |
| `trace_process()` | 继续使用物理 socket ID |
| socket role、trace ID、协议状态 | 不修改 |
| 发送给用户态的 `socket_id` | UDP 且五元组完整时改写为 peer socket ID |
| 发送给用户态的 `data_seq` | UDP 且五元组完整时改写为 peer seq，用户态对应 `cap_seq` |
| TCP、Unix Socket、文件 IO 等 | 完全不受影响 |

换句话说，物理 `socket_id/seq` 仍负责 eBPF 内部状态；peer `socket_id/seq` 只是一层出站
元数据映射。

本文不设计或修改 `reasm_seg`。

## 3. 目标与非目标

### 3.1 目标

1. 同一物理 UDP socket 与不同 peer 通信时，输出不同的 `socket_id`。
2. 同一个“物理 socket + peer 五元组”在双向通信中使用同一个 peer `socket_id`。
3. 每个 peer 独立生成从 0 开始的 `cap_seq`，语义与现有物理 socket seq 一致。
4. FD 被复用、Map 并发创建或 LRU 淘汰时，不把新数据错误归入旧 Flow。
5. 地址不完整或新逻辑失败时，安全回退到现有物理 `socket_id/seq`。
6. 不改变传给用户态的事件结构，不要求用户态为该功能增加新的字段。

### 3.2 非目标

1. 不改变 eBPF 内部协议推断、trace 关联或其他 socket 状态的归属方式。
2. 不为物理 socket 的 close 事件枚举并关闭所有 peer Flow。
3. 第一阶段不支持同一次 `sendmmsg()` 中不同消息使用不同目标地址；现有附加消息仍沿用
   第一条消息的 tuple。
4. 不保证 LRU 淘汰后同一 peer 继续使用原 ID；被淘汰后再次出现时应创建一个新 Flow。

## 4. 总体方案

新增一个 `BPF_MAP_TYPE_LRU_HASH`：

```text
PeerKey
  └─ physical_socket_id + local endpoint + remote endpoint
       ↓ lookup/create
PeerState
  └─ peer_socket_id + seq
       ↓ only rewrite outgoing metadata
__socket_data.socket_id = peer_socket_id
__socket_data.data_seq  = peer_seq
```

完整数据路径如下：

```text
syscall enter/exit
    ↓
现有协议识别、地址提取、trace 和 socket_info_map 处理
    ↓
__data_submit() 生成完整 tuple，并先写入物理 socket_id/seq
    ↓
output_data_common()
    ↓
在数据提交给用户态前，根据最终 tuple 查询 udp_peer_map
    ↓
只覆盖当前 __socket_data 的 socket_id/data_seq
    ↓
perf output → 用户态 socket_id/cap_seq
```

选择输出阶段改写有三个原因：

1. 此时 UDP 本地地址补偿和 syscall 参数中的远端地址均已处理，tuple 最完整。
2. `trace_process()`、协议识别和 `socket_info_map` 已经使用完物理 ID，不会被 peer ID 影响。
3. 避免继续扩大 `__data_submit()` 和协议推断程序，降低旧内核 4096 指令限制以及新内核
   verifier 路径探索超限的风险。

## 5. Map 设计

### 5.1 Key

```c
struct udp_peer_key_t {
	__u64 physical_socket_id;
	__u8 local_addr[16];
	__u8 remote_addr[16];
	__u16 local_port;
	__u16 remote_port;
	__u8 addr_len;
	__u8 reserved[3];
};
```

字段来源：

| PeerKey 字段 | `struct __socket_data` 来源 | 含义 |
| --- | --- | --- |
| `physical_socket_id` | 改写前的 `socket_id` | `socket_info_s.uid` |
| `local_addr` | `tuple.rcv_saddr` | 本地 IP |
| `remote_addr` | `tuple.daddr` | 远端 IP |
| `local_port` | `tuple.num` | 本地端口 |
| `remote_port` | `tuple.dport` | 远端端口 |
| `addr_len` | `tuple.addr_len` | 4 或 16 |

Key 不包含数据方向。`tuple.rcv_saddr/num` 始终表示本地端，`tuple.daddr/dport` 始终表示
远端，因此同一 peer 的请求和响应能够命中同一条 Map 记录。

构造 Key 时必须先整体清零。IPv4 只复制地址数组的前 4 字节，后 12 字节保持为零，避免
未初始化数据造成相同 IPv4 生成不同 Hash Key。端口直接使用 tuple 中已经统一的表示。

`physical_socket_id` 必须放入 Key。即使进程关闭 FD 后又复用了相同 FD，新物理 socket 也会
获得新的物理 ID，因此不会误命中旧 peer。

### 5.2 Value

```c
struct udp_peer_state_t {
	__u64 socket_id;
	volatile __u64 seq;
};
```

- `socket_id`：发送给用户态的 peer socket ID。
- `seq`：当前已分配序号；新 Value 初始化为 `UINT64_MAX`，首次原子加后为 0。

不在 Value 中保存协议、方向或其他 socket 状态，避免把原有逻辑迁入 peer Map。

### 5.3 Map 类型与容量

```c
struct bpf_map_def SEC("maps") __udp_peer_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct udp_peer_key_t),
	.value_size = sizeof(struct udp_peer_state_t),
	.max_entries = MAP_MAX_ENTRIES_DEF,
	.feat_flags = FEATURE_FLAG_SOCKET_TRACER,
};
```

这里的 40960 是功能开启时的容量。功能关闭时，用户态必须在 BPF 对象加载前通过
`maps_config(tracer, MAP_UDP_PEER_NAME, 1)` 把 `max_entries` 调整为 1，具体原因和加载流程见
第 10 节。

### 5.4 内存估算与推荐容量

每个条目的 Key 为 48 字节，Value 为 16 字节，Key+Value 有效载荷为 64 字节。实际内核内存
还包括 Hash 节点、LRU 节点、bucket、锁、对齐和内存分配器开销。不同内核实现存在差异，
下表用有效载荷的约 2～3 倍估算实际占用，仅用于容量规划：

| `max_entries` | 可保存的活跃 PeerKey | Key+Value 有效载荷 | 预计内核实际占用 |
| ---: | ---: | ---: | ---: |
| 4,096 | 约 4 千 | 0.25 MiB | 约 0.5～1 MiB |
| 16,384 | 约 1.6 万 | 1 MiB | 约 2～3 MiB |
| **40,960** | **约 4 万** | **2.5 MiB** | **约 5～8 MiB** |
| 65,536 | 约 6.5 万 | 4 MiB | 约 8～12 MiB |
| 131,072 | 约 13 万 | 8 MiB | 约 16～24 MiB |
| 524,288 | 约 52 万 | 32 MiB | 约 64～96 MiB |

**推荐值：`max_entries = 40960`。**

推荐 40960 的原因：

1. 与项目现有 `MAP_MAX_ENTRIES_DEF` 一致，不需要新增容量配置和加载期 Map resize 逻辑。
2. 可同时保存约 4 万个活跃 UDP PeerKey，能够覆盖第一阶段常规 DNS、服务发现和 UDP 服务端
   多 peer 场景。
3. 预计增加约 5～8 MiB 内核内存，明显低于直接复用 131072 或 524288
   `max_socket_entries` 可能带来的内存成本。
4. 容量不足时由 LRU 淘汰冷 peer，不会因为 Map 满而停止创建新 peer。

这里的容量表示“当前保留的活跃/近期 PeerKey 数量”，不是进程运行期间累计访问过的 peer
总数。第一阶段不直接复用可能被配置到数十万的 `max_socket_entries`。如果现场长期活跃 peer
确实超过 4 万，再单独增加 `max_udp_peer_entries` 配置；不建议预先把默认值放大到 131072
或 524288。

LRU Hash 通常在 Map 创建时预留主要内存，因此即使当前条目很少，也不能按实际条目数估算
其内存。设计验收时必须在目标 3.10、4.14 和较新内核上读取 BPF Map 的实际 memlock/内存
信息，以实测结果为准。

功能默认关闭时 `max_entries = 1`，只保留满足 BPF ELF 重定位和 Map 创建要求的最小容量，
不会预分配 40960 项对应的约 5～8 MiB。单 entry Map 仍有 bucket、Map 对象和页级分配开销，
实际通常为 KiB 级，仍以目标内核实测为准。

选择 LRU 的原因：

- UDP 没有可靠的连接建立和关闭生命周期，无法准确知道某个 peer 何时结束。
- 物理 socket close 时无法通过 BPF Map API 高效枚举并删除该 socket 的全部 peer。
- LRU 能让活跃 peer 保留，并自动淘汰长期不活跃 peer，不需要额外定时清理链路。

## 6. peer socket ID 分配

peer ID 继续复用 `tracer_ctx->socket_id` 生成器，不另建随机 ID 或 Hash ID。

现有生成器按 CPU 初始化：高 8 位为 CPU ID，其余位由启动时间基值和递增值组成。每个 CPU
可无锁递增，同时不同 CPU 生成的 ID 不冲突。物理 socket ID 与 peer socket ID 共用该生成器，
因此两类 ID 也不会冲突。

Map miss 时执行：

1. 从当前 CPU 的 `tracer_ctx->socket_id` 分配一个候选 ID。
2. 构造 `seq = UINT64_MAX` 的初始 Value。
3. 使用 `BPF_NOEXIST` 插入，不能使用 `BPF_ANY` 覆盖其他 CPU 已创建的同一 peer。
4. 无论插入成功还是因并发竞争失败，都重新 lookup Map：
   - 若 lookup 成功，使用 Map 中最终状态的 `socket_id`，并通过原子加分配序号；
   - 若 lookup 失败，保留事件原有的物理 `socket_id/seq`。
5. 只在 state lookup 成功且序号已分配后，才同时改写事件的
   `socket_id/data_seq`。

插入成功不代表当前代码已经持有可用的 Map Value 指针，而且新条目可能在随后
lookup 前被 LRU 淘汰。因此禁止在插入成功分支中提前改写事件，避免出现已换成
peer `socket_id`、却没有可用 peer state 或沿用物理 seq 的半改写事件。

竞争失败时允许候选 ID 跳号。ID 连续性没有语义，唯一性比连续性重要。

## 7. peer seq 分配

SEQ 按“Socket Tracer 实际成功生成的输出事件数”分配，而不是按 syscall 参数或 syscall
返回的消息数提前预留。

每成功生成一个输出事件，只执行一次原子加：

```c
__sync_fetch_and_add(&state->seq, 1);
event->socket_id = state->socket_id;
event->data_seq = state->seq;
```

项目用于 3.10/4.14 变体的 LLVM 11 BPF 后端不允许消费 XADD 指令的返回值，
否则编译报 `Invalid usage of the XADD return value`。因此本实现与现有
`socket_info_s.seq` 保持一致，采用“原子加后读取”，不使用原子 fetch-and-add
返回值。

该写法能确保计数器的原子递增，但不是线性化的“取号+递增”：当同一 peer 同时在
多 CPU 上执行时，原子加之后的读取可能观察到其他 CPU 更新后的值。这一限制与
当前物理 socket seq 一致，第一阶段不引入旧内核不支持的 BPF 自旋锁或新原子
指令。

普通 syscall 成功生成一个事件时分配一个 SEQ。

`sendmmsg()` 需要区分三个不同概念：

1. `vlen`：用户在入口提交的消息数量上限；
2. `mmsg_count`：syscall 返回的成功处理消息数量；
3. Socket Tracer 实际捕获并加入输出缓冲区的事件数量。

`vlen >= 2` 或 `mmsg_count >= 2` 都不能直接作为分配两个 SEQ 的依据。例如
`mmsg_count == 2` 时，第二条消息仍可能因为不是当前支持的 DNS 附加消息、读取用户内存失败、
长度无效或数据复制失败而没有生成第二个 eBPF 输出事件。

因此 `sendmmsg()` 按以下时机分配：

```text
主事件成功生成
    → 原子分配一个 SEQ

output_extra_data_common() 成功完成第二条数据复制，
并把第二个事件加入 data_buf
    → 再原子分配一个 SEQ

output_extra_data_common() 返回失败或没有生成第二个事件
    → 不分配第二个 SEQ
```

不能继续使用 `extra_v->data_seq = head->data_seq + 1` 直接推导第二条序号，否则另一个 CPU
可能已经推进了同一 peer 的序号。第二条事件成功构造后，也必须在同一个
peer state 上单独执行一次原子加。

由于第二个 SEQ 在第二个事件实际构造成功后才分配，如果同一 peer 被多个线程或 CPU 并发
操作，同一次 `sendmmsg()` 的两条事件之间可能插入另一个事件的 SEQ。因此不承诺
同一次 syscall 的两条事件在并发场景下绝对连续。

这里的“实际输出”是指事件已经成功构造并加入 eBPF 输出缓冲区。perf buffer 满等原因造成的
最终投递失败无法获得用户态确认，也不能回滚已经分配的 SEQ。

## 8. 元数据改写条件

只有同时满足以下条件才查询或创建 peer Map：

1. `event->tuple.l4_protocol == IPPROTO_UDP`；
2. 不是 close 事件；
3. 功能开关已开启；
4. 改写前的物理 `socket_id != 0`；
5. `addr_len` 为 4 或 16；
6. 本地、远端端口均非 0；
7. 本地、远端地址均有效且完整。

任一条件不满足时，保持 `__data_submit()` 已写入的物理 `socket_id/data_seq`。特别是本地 IP
仍为 `0.0.0.0` 或 `::` 时，不创建缺少本地端点的 PeerKey。对于未 bind 或通配地址 UDP
socket，本 v6.6 回迁版本不包含 UDP 内核 Hook 本地 IP 补偿，需要应用绑定具体本地地址
以获得完整 PeerKey。

Map lookup、创建或竞争恢复失败时也必须整体回退，不能只改写 `socket_id` 而保留物理 seq，
也不能只改写 seq。

## 9. 插入位置

正常 socket 数据最终都通过 tail call 进入 `output_data_common()`，因此只在该输出程序中调用
peer 元数据 helper。`__output_data_common()` 当前只服务于新内核的 close/IO 兜底路径，不生成
具备完整 UDP 五元组的普通数据事件；不得把 peer Map 路径加入其中。否则 LLVM 会把这段逻辑
合并进 `df_T_exit_sendmsg` 等大型 syscall 程序，在部分新内核上触发 verifier 百万路径上限。

helper 的调用位置必须满足：

1. `__data_submit()` 已完成最终 tuple 和物理 `socket_id/seq` 的写入；
2. 主事件的 `output_data_copy()` 已成功，确认当前事件会加入输出缓冲区；
3. 位于当前事件执行 `finalize_data_output()` 之前；
4. 位于 `output_extra_data_common()` 复制事件头之前，使附加消息继承 peer `socket_id`；
5. 附加事件只在自身 `output_iov_data_copy()` 成功后分配第二个 SEQ；
6. 对已经缓存在 `data_buf` 中的其他事件不做扫描或二次改写。

建议 helper 只负责以下工作：校验 UDP tuple、构造 Key、lookup/create、分配一个序号、覆盖当前
事件头。不要在 helper 中调用协议推断、更新 `socket_info_map` 或维护其他业务状态。

主事件 helper 不返回 Map Value 指针，只返回普通标量 `peer_socket_id`，并通过参数保留使用
物理 `socket_id` 构造的 PeerKey。伪代码如下：

```c
static __always_inline __u64 rewrite_udp_peer_metadata(
	struct __socket_data *event,
	struct tracer_ctx_s *tracer_ctx,
	struct udp_peer_key_t *key)
{
	if (!udp_peer_metadata_enabled() || !valid_complete_udp_tuple(event))
		return 0;

	build_udp_peer_key(key, event); // 此时 event->socket_id 还是物理 ID

	struct udp_peer_state_t *state = udp_peer_map__lookup(key);
	if (!state) {
		struct udp_peer_state_t new_state = {
			.socket_id = alloc_socket_id(tracer_ctx),
			.seq = (__u64)-1,
		};
		bpf_map_update_elem(&__udp_peer_map, key, &new_state,
				    BPF_NOEXIST);
		state = udp_peer_map__lookup(key);
		if (!state)
			return 0; // 保留物理元数据
	}

	__sync_fetch_and_add(&state->seq, 1);
	__u64 peer_socket_id = state->socket_id;
	event->socket_id = peer_socket_id;
	event->data_seq = state->seq;
	return peer_socket_id;
}
```

Linux 4.14 verifier 无法在附加消息的数据复制 helper 调用之后继续保留 Map Value 指针类型。
因此主事件只把栈上的 PeerKey 和标量 `peer_socket_id` 传给
`output_extra_data_common()`，不得跨 helper 保存或传递 `udp_peer_state_t *`。

调用顺序固定为：

```c
struct udp_peer_key_t peer_key = {};
__u64 peer_socket_id =
    rewrite_udp_peer_metadata(v, tracer_ctx, &peer_key);

if (need_finalize)
	finalize_data_output(ctx, tracer_ctx, curr_time, diff, v_buff);

output_extra_data_common(args, v_buff, v, &peer_key, peer_socket_id,
			 max_size, reassembly_bytes);
```

附加事件必须在 Payload 复制成功后，使用保存的 PeerKey 重新 lookup Map，并校验查到的
`state->socket_id` 是否仍等于主事件的 `peer_socket_id`。原因是：

1. PeerKey 在主事件改写前使用物理 `socket_id` 构造，能够稳定定位同一个逻辑 peer。
2. Map Value 指针不跨越 `bpf_perf_event_output()`、用户内存读取或 Payload 复制 helper，满足
   Linux 4.14 verifier 的指针生命周期约束。
3. 重新 lookup 后校验实例 ID，可以识别条目已被 LRU 淘汰并重建的情况。
4. 实例缺失或 ID 不一致时必须放弃附加事件，不能回退到物理 ID，否则同一次
   `sendmmsg()` 会被拆到两个逻辑 Socket。
5. 复制成功后才 lookup 和取号，附加数据读取或复制失败时不会无故消耗序号。

`output_extra_data_common()` 的关键顺序如下：

```c
static __always_inline int output_extra_data_common(
	struct data_args_t *args,
	struct __socket_data_buffer *v_buff,
	struct __socket_data *head,
	struct udp_peer_key_t *peer_key,
	__u64 peer_socket_id,
	int max_size,
	__u32 reassembly_bytes)
{
	// 省略条件、长度和缓冲区检查
	bpf_probe_read_kernel(extra_v, DATA_HEADER_SIZE, head);
	int copy_bytes = output_iov_data_copy(...);
	if (copy_bytes < 0)
		return -1;

	if (peer_socket_id) {
		struct udp_peer_state_t *state =
		    udp_peer_map__lookup(peer_key);
		if (!state || state->socket_id != peer_socket_id)
			return -1;

		__sync_fetch_and_add(&state->seq, 1);
		extra_v->socket_id = peer_socket_id;
		extra_v->data_seq = state->seq;
	} else {
		// 功能关闭或主事件回退时保持原有行为。
		extra_v->data_seq = head->data_seq + 1;
	}

	// 只有上述步骤成功后才提交附加事件。
	...
}
```

为控制旧内核 verifier 的状态空间，主 iovec 路径仍保留 18 次展开；当前只服务于第二条 DNS
A/AAAA 消息的附加路径支持前 8 个 iovec，空项同样占用一个展开次数。该值已在 Linux 4.14
和 4.19 上完成实际加载与分段报文验证，候选值对比及边界见
[附加 iovec 上限测试报告](udp-extra-iov-limit-test-report-20261124.md)。实际实现还需要避免
栈膨胀，并按 4.14 verifier 能接受的方式读取 packed event 字段；伪代码只表达语义，
不规定最终局部变量形态。

## 10. 配置开关

新增配置：

```yaml
inputs:
  ebpf:
    socket:
      tunning:
        udp_peer_id_enabled: false
```

### 10.1 默认值与生效方式

- 默认关闭，保证版本升级后 UDP `socket_id/cap_seq` 语义不自动变化。
- 修改方式为 `agent_restart`，不支持运行时热切换，避免存量 Flow 同时出现物理 ID 和 peer ID。
- 开启后，UDP 输出按“物理 socket + peer 五元组”区分。
- 关闭后，BPF 程序跳过 PeerKey 构造和 LRU Map 操作，输出保持原物理 `socket_id/seq`。
- 开关只控制元数据改写，不控制 UDP 地址采集；地址不完整时仍按第 8 节回退。

### 10.2 关闭时仍创建单 entry Map

**确定方案：关闭时仍创建 `BPF_MAP_TYPE_LRU_HASH`，但把 `max_entries` 设置为 1；不采用完全
不创建 Map 的方案。**

原因如下：

1. 同一个 BPF 对象中的输出程序引用了 `__udp_peer_map`。加载器解析 ELF relocation 并加载
   程序时需要有效 Map FD；运行时开关为 false 不代表加载器或 verifier 可以省略该 Map。
2. 完全不创建 Map 需要额外生成“不包含 peer Map 和相关指令”的 BPF 二进制变体，并在启动
   时选择对象，会增加编译产物、加载分支和内核兼容性测试范围。
3. 通过现有 `maps_config()` 接口在加载前把 peer Map 的 `max_entries` 调整为 1，
   不引入其他功能的 Map 或 Hook。
4. 单 entry LRU Map 的内存很小，并且 BPF 运行路径会先检查开关，不会实际访问或写入该 Map。

该方案只减少关闭状态的 Map 内存和运行时操作，**不会减少 BPF 程序指令数，也不会让
verifier 跳过 peer 分支**。运行时开关的两个分支在加载时仍需通过 verifier。如果新增代码使
某个内核再次出现指令或路径探索超限，只能继续压缩 helper，或引入不包含 peer 代码的独立
BPF 二进制变体；把 LRU Map 缩为 1 不能解决 verifier 容量问题。

### 10.3 加载流程

建议完全复用现有 UDP 本地 IP 开关的处理方式：

```text
读取配置，默认 false
    ↓
set_udp_peer_id_enabled(false/true)
    ↓
setup_bpf_tracer() 打开 BPF 对象，但尚未创建 Map
    ↓
enabled == false
    → maps_config(tracer, MAP_UDP_PEER_NAME, 1)

enabled == true
    → 保持 MAP_MAX_ENTRIES_DEF，即 40960
    ↓
tracer_bpf_load() 创建全部 Map 并加载程序
    ↓
把 enabled 值写入单 entry udp_peer_id_enabled_map
```

配置和用户态接口建议包括：

```c
#define MAP_UDP_PEER_NAME "__udp_peer_map"
#define MAP_UDP_PEER_ENABLED_NAME "__udp_peer_id_enabled_map"

void set_udp_peer_id_enabled(bool enabled);
```

BPF 侧必须先判断 UDP 协议，再查询单 entry 开关 Map；关闭时立即返回，不能构造 PeerKey，
也不能 lookup/update `udp_peer_map`：

```c
if (event->tuple.l4_protocol != IPPROTO_UDP)
	return NULL;
if (!udp_peer_id_is_enabled())
	return NULL;
```

开关 Map 只包含一个 `__u32` 值，默认 0。加载完成后若写入开关 Map 失败，应视为 Socket
Tracer 启动失败，避免用户配置开启但内核仍按物理 ID 输出。

### 10.4 配置接入点

实现时需要同步以下层次，命名保持一致：

| 层次 | 修改内容 |
| --- | --- |
| Agent 配置 | `EbpfSocketTunning` 增加 bool 字段，`Default` 为 `false` |
| 配置模板 | 增加 `udp_peer_id_enabled: false` |
| 配置更新 | 标记为 `agent_restart`，加入重启原因 |
| 启动校验 | peer ID 开启时提示本分支无法补偿通配地址的本地 IP |
| Rust/C FFI | 增加 `set_udp_peer_id_enabled(bool)` |
| Socket Tracer 用户态 | 保存开关；加载前把关闭状态的 peer Map 调整为 1 |
| BPF 开关 Map | 加载后写入 0/1，BPF 输出路径读取该值 |

第一阶段不增加 `max_udp_peer_entries` 配置。开启时固定使用 40960，关闭时固定使用 1，先用
回归和现场数据验证容量与内存，再决定是否开放容量调节。

### 10.5 v6.6 的 UDP 本地 IP 限制

`udp_peer_id_enabled` 依赖完整本地/远端地址构造 PeerKey。本 v6.6 回迁版本不提供
UDP 内核 Hook 本地 IP 补偿，因此 bind 到 `0.0.0.0` 或 `::` 的
UDP socket 可能无法补齐实际本地 IP，相关事件会按第 8 节持续回退到物理
`socket_id/seq`。

该配置组合不得阻止 Socket Tracer 启动，也不得自动改写用户配置。Agent 应在每次
Socket Tracer 启动时最多输出一次 INFO，明确提示 peer 隔离对通配地址 UDP socket 可能
不生效。建议日志语义为：

```text
UDP peer socket ID isolation requires complete local and remote endpoints;
wildcard UDP sockets may fall back to physical socket IDs because the local IP is unavailable on this branch.
```

## 11. 生命周期与 LRU 语义

### 11.1 正常命中

同一物理 socket 和同一组本地/远端地址端口持续命中同一 Value，获得稳定 peer ID 和递增
seq。收发方向共用该状态。

### 11.2 FD 复用

新物理 socket 会获得新的物理 ID，PeerKey 随之变化。即使 PID、FD 和五元组全部相同，也会
创建新的 peer ID，不会继承旧 seq。

### 11.3 LRU 淘汰

记录被淘汰后，同一 peer 再次出现会分配新 peer ID，并从 seq 0 开始。用户态表现为新 Flow，
不会把两段生命周期错误拼接。

### 11.4 socket close

现有 close 事件没有完整 peer tuple，仍携带物理 socket ID。本方案不扫描 `udp_peer_map`，也
不生成多个 peer close 事件。用户态 peer Flow 依赖现有超时机制回收；Map 项由 LRU 淘汰。

## 12. 性能与内存影响

每个具备完整 tuple 的 UDP 输出事件增加：

- 一次 LRU Hash lookup；
- 命中时一次 64 位原子加法；
- miss 时一次 ID 分配、一次 `BPF_NOEXIST` update；
- 并发 miss 竞争失败时额外一次 lookup。

TCP 和其他数据源只增加一个非常短的协议判断并立即返回。为了控制 verifier 和运行时成本，
PeerKey 构造及 Map 操作必须放在独立小 helper 中，且只在确认 UDP、开关开启后执行。

需要关注的高成本场景是源地址/源端口随机变化的 UDP 扫描或攻击流量：此时几乎每条数据都
是 Map miss，并持续触发 LRU 淘汰。开关提供紧急回退能力；后续可根据压测结果增加创建速率、
Map update 失败和回退计数。

## 13. 兼容性影响

### 13.1 用户态

不修改 `struct __socket_data` 或 `struct socket_bpf_data`。用户态继续读取原字段：

```text
sd->socket_id  ← peer socket ID
sd->data_seq   ← Rust/C 用户态中的 cap_seq
```

`generate_ebpf_flow_id()` 会自然使用新的 peer ID，因此不同 peer 进入不同 Flow；基于 cap seq 的
调用日志聚合也会在每个 peer 内独立进行。无需在用户态重新计算 ID 或增加 PeerKey Map。

### 13.2 内核版本

本设计以项目当前支持的内核均具备 `BPF_MAP_TYPE_LRU_HASH` 能力为前提，不设计非 LRU Map
降级路径，也不为关闭状态增加另一套 BPF 二进制。实现后仍需验证 64 位 Map Value 原子加法、
`BPF_NOEXIST` 和相关程序在项目支持的内核变体上能够创建和通过 verifier，重点包括 3.10
发行版内核与 4.14 内核。功能关闭时也必须验证单 entry LRU Map 能够正常创建。

### 13.3 socket ID 位布局

peer ID 使用现有生成器，保持当前 socket ID 位布局。用户态
`generate_ebpf_flow_id()` 会覆盖第 48～55 位为数据源；本设计不改变这一既有行为，也不使用
Hash 截断值作为 peer ID。

## 14. 可观测性建议

建议增加以下统计，便于判断回退和 Map 压力：

| 统计项 | 含义 |
| --- | --- |
| `udp_peer_lookup_hit` | PeerKey 命中次数 |
| `udp_peer_create` | 新 peer 创建成功次数 |
| `udp_peer_create_race` | `BPF_NOEXIST` 竞争后命中胜者次数 |
| `udp_peer_invalid_tuple` | tuple 不完整而保留物理元数据次数 |
| `udp_peer_update_fail` | 创建失败且无法恢复次数 |

统计不是第一版正确性的前置条件，但至少应在调试日志或控制接口中能确认 Map 已创建、容量和
功能开关状态。

## 15. 测试计划

### 15.1 核心功能

1. 一个 UDP 服务端 socket/FD，同时接收客户端 A、B：
   - A 与 B 的输出 `socket_id` 不同；
   - A 的请求和响应 `socket_id` 相同；
   - B 的请求和响应 `socket_id` 相同。
2. 无同 peer 跨 CPU 并发时，每个 peer 的 `cap_seq` 独立从 0 开始并递增，
   不出现重复。
3. 交错顺序 `A 请求 → B 请求 → B 响应 → A 响应` 下：
   - A 序列只受 A 数据影响；
   - B 序列只受 B 数据影响。
4. 两个物理 socket 与同一远端通信时，peer ID 不同。
5. 关闭并复用相同 FD 后，peer ID 不复用。

### 15.2 syscall 回归

分别验证 UDP：

- `sendto()` / `recvfrom()`；
- `sendmsg()` / `recvmsg()`；
- `sendmmsg()` / `recvmmsg()`；
- connected UDP 的 `send()` / `recv()`；
- IPv4、IPv6、AF_INET6 双栈使用 IPv4 peer。

### 15.3 `sendmmsg()` 附加事件

DNS A + AAAA 两条事件应满足：

- 两条事件具有相同 peer `socket_id`；
- 无并发时两条 `cap_seq` 连续；存在同 peer 并发时允许其他事件的 SEQ 插入；
- 无同 peer 跨 CPU 并发时，下一次事件的 `cap_seq` 不与已有事件重复；
- `vlen >= 2` 或 `mmsg_count >= 2`，但只生成一个 eBPF 事件时，仅分配一个序号；
- 只有第二条事件成功加入输出缓冲区时才分配第二个序号；
- 第二条读取或复制失败时不消耗 SEQ。
- 主事件经过 `finalize_data_output()` 输出后，附加事件重新 lookup Map 并校验实例 ID；
  校验成功时两条事件的 peer `socket_id` 一致，校验失败时放弃附加事件。

### 15.4 回退

1. 默认不配置或显式关闭 `udp_peer_id_enabled`：
   - 输出与修改前一致；
   - `udp_peer_map.max_entries == 1`；
   - peer Map 中没有运行时创建的 peer 状态。
2. 开启功能后，`udp_peer_map.max_entries == 40960`。
3. 本地 IP、远端 IP 或端口不完整，保留物理 `socket_id/seq`。
4. 人为缩小 Map 并制造大量 peer，Socket Tracer 继续运行且不输出半改写元数据。
5. 在本分支开启 `udp_peer_id_enabled`：
   - Socket Tracer 正常启动，不自动修改开关；
   - 每次 Socket Tracer 启动最多输出一次明确 INFO 提示；
   - bind 到通配地址且无法补齐本地 IP 的 UDP 事件保留物理
     `socket_id/seq`，不产生不完整 PeerKey；
   - 已具备完整本地/远端地址的 UDP 事件仍正常使用 peer `socket_id/cap_seq`。

### 15.5 性能与资源

对比功能开关前后：

- 单 peer 高 PPS 的 CPU 开销；
- 高 peer churn 的 CPU 开销；
- `udp_peer_map` 实际内存和 memlock 占用；
- perf lost、Map update 失败和 Socket Tracer 状态。

### 15.6 内核兼容性

至少覆盖项目现有回归矩阵中的 3.10、4.14、4.19、5.4、5.10、5.15 和 6.x；验证内容包括：

- eBPF 对象与 LRU Map 创建成功；
- 开关关闭时单 entry LRU Map 创建成功；
- verifier 能够验证栈上 PeerKey 和标量 peer ID 跨越复制、输出 helper；Map Value 指针只在
  最后一次 lookup 后使用，且中间不再调用 helper；
- Socket Tracer 达到 `TRACER_RUNNING`；
- 核心双 peer 用例的 `socket_id/cap_seq` 符合预期。

## 16. 验收标准

满足以下条件后可以进入代码合并：

1. 同一物理 UDP FD 的不同 peer 在 datadump/Rust callback 中显示不同 `socket_id`。
2. 同一 peer 的双向数据使用同一 `socket_id`；无同 peer 跨 CPU 并发时，
   `cap_seq` 独立且不重复。
3. `socket_info_map.uid/seq`、`trace_process()` 和协议识别路径没有改用 peer 状态。
4. TCP、Unix Socket 及文件 IO 回归结果与修改前一致。
5. 4.14 verifier 正常，新内核无 `1,000,001 insns` 路径探索失败。
6. 支持矩阵内的 Socket Tracer 在开关开启和关闭时均可加载 LRU Map 并正常运行。
7. Map 压力或地址不完整时只回退到物理元数据，不产生 `socket_id` 与 `cap_seq` 分属两套状态
   的事件。
8. peer ID 开启但 UDP 本地 IP 关闭时不阻塞启动，且每次 Socket Tracer 启动最多
   输出一次明确的 INFO 提示。
