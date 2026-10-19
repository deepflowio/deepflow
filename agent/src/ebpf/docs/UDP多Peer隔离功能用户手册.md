# UDP 多 Peer 隔离功能用户手册

## 1. 功能说明

UDP 服务端通常使用同一个 socket FD 接收多个客户端的数据。默认情况下，Socket Tracer
使用物理 socket 生成 `socket_id` 和 `cap_seq`，因此共用该 FD 的不同客户端可能被上层
误认为同一条 Flow。

开启 UDP 多 Peer 隔离后，Socket Tracer 使用以下信息区分逻辑连接：

```text
物理 socket_id + 本地 IP/端口 + 远端 IP/端口
```

每个完整 PeerKey 会获得独立的 `socket_id` 和从 0 开始递增的 `cap_seq`。该功能只改写
提交给用户态的事件元数据，不改变 eBPF 内部的协议识别、物理 socket 状态和分段重组状态。

## 2. 适用场景

建议在以下条件同时满足时开启：

- 采集 UDP 调用日志；
- 一个 UDP FD 会和多个客户端或上游通信；
- 上层需要根据 `socket_id` 和 `cap_seq` 聚合请求与响应；
- 已观察到不同五元组的 UDP 请求、响应被错误合并。

如果一个 UDP FD 始终只对应一个 peer，保持默认关闭即可。

## 3. 配置方法

配置项位于 `inputs.ebpf.socket.tunning`。注意字段名是仓库现有的 `tunning`，不要改写为
`tuning`。

本 v6.6 回迁版本仅提供 peer 隔离，不包含 UDP 内核 Hook 本地 IP 补偿。建议应用绑定具体本地 IP：

```yaml
inputs:
  ebpf:
    socket:
      tunning:
        udp_peer_id_enabled: true
```

配置修改需要重启 deepflow-agent 后生效。

| 配置项 | 默认值 | 作用 |
| --- | --- | --- |
| `udp_peer_id_enabled` | `false` | 按物理 socket 和完整本地、远端端点分配 peer `socket_id/cap_seq`。 |

当 `udp_peer_id_enabled=true` 时，功能可启动；但 bind 到
`0.0.0.0` 或 `::` 的 socket 可能无法形成完整 PeerKey，相关事件会回退到物理
`socket_id/cap_seq`，Agent 日志会输出一次 INFO 提示。

## 4. 使用 deepflow-ctl 下发配置

### 4.1 查询 Agent Group

```bash
deepflow-ctl agent-group list
```

服务端不在默认地址时增加 `-i <deepflow-server-ip>`；多组织环境同时增加
`--org-id <org-id>`。

### 4.2 备份当前完整配置

```bash
GROUP_ID=g-xxxxxx
deepflow-ctl agent-group-config list "$GROUP_ID" -o yaml \
  > deepflow-agent-config.before-udp-peer.yaml
test -s deepflow-agent-config.before-udp-peer.yaml
```

`agent-group-config update` 会替换该 Group 的完整自定义配置。必须在原配置中合并第 3 节的
字段，不能用只包含测试字段的不完整 YAML 覆盖共享环境配置。

### 4.3 更新并确认配置

```bash
cp deepflow-agent-config.before-udp-peer.yaml deepflow-agent-config.yaml
# 编辑 deepflow-agent-config.yaml，合并第 3 节配置

deepflow-ctl agent-group-config update "$GROUP_ID" \
  -f deepflow-agent-config.yaml

deepflow-ctl agent-group-config list "$GROUP_ID" -o yaml
```

如果该 Group 尚未创建自定义配置，首次下发时使用 `agent-group-config create`。

### 4.4 确认 Agent 重启并生效

等待配置同步和 Agent 重启后检查日志：

```bash
journalctl -u deepflow-agent --since '10 minutes ago' \
  | grep -E 'UDP peer socket ID isolation|TRACER_RUNNING'
```

容器化部署时请从 deepflow-agent 容器日志中执行同等检查。Socket Tracer 必须进入
`TRACER_RUNNING`；日志中不应出现 eBPF verifier、Map 创建或程序加载失败。

## 5. 结果判断

对同一个服务端 PID 和 FD，假设客户端 A、B 交错通信：

```text
A 请求 → B 请求 → B 响应 → A 响应
```

开启功能后的预期结果：

| Peer | 请求 socket_id/cap_seq | 响应 socket_id/cap_seq |
| --- | --- | --- |
| A | `peer_socket_id_A / 0` | `peer_socket_id_A / 1` |
| B | `peer_socket_id_B / 0` | `peer_socket_id_B / 1` |

其中 `peer_socket_id_A != peer_socket_id_B`。同一 peer 的请求和响应使用相同
`socket_id`，但不同 peer 的序号互不影响。

以下情况会保留物理 `socket_id/cap_seq`：

- 本地或远端 IP 为零；
- 本地或远端端口为零；
- 不是 IPv4/IPv6 UDP 数据事件；
- socket close 事件；
- peer Map 查询或创建失败。

## 6. 使用仓库样例验证

仓库提供 `@agent/src/ebpf/test/udp-peer-id` 样例：

- 服务端只创建一个 UDP FD，并绑定 `127.0.0.1:53053`；
- 客户端 A、B 分别绑定 `127.0.0.2`、`127.0.0.3`；
- 请求顺序为 A、B，响应顺序为 B、A；
- 校验脚本检查两个 peer 的 `socket_id` 不同，且每个 peer 的 `cap_seq` 为 `0,1`。

详细命令见 `@agent/src/ebpf/test/udp-peer-id/README.md`。

Socket Tracer Rust sample 会在加载前显式执行：

```rust
set_udp_peer_id_enabled(true);
```

该 sample 仅用于开发测试；正式 Agent 是否开启仍由 Group 配置决定。

## 7. 性能与资源

功能开启后，每个具备完整五元组的 UDP 事件会增加一次 LRU Hash 查询；首次出现的 peer
还会创建 Map 项。当前 `udp_peer_map` 容量固定为 40960。功能关闭时 Map 容量缩小为 1，
且运行路径不会查询或写入 peer Map。

高 PPS、高 peer churn 或源地址随机变化场景应重点观察 Agent CPU、perf lost 和 eBPF Map
压力。如果资源开销不可接受，可关闭该配置并重启 Agent。

## 8. 关闭与回滚

将配置改回：

```yaml
inputs:
  ebpf:
    socket:
      tunning:
        udp_peer_id_enabled: false
```

重新下发并等待 Agent 重启。关闭后，新产生的 UDP 事件恢复使用物理
`socket_id/cap_seq`。不要在同一次问题分析中混合使用开关前后的 Flow 数据。
