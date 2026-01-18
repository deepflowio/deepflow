# 全局配置 {#global}

## 资源限制 {#global.limits}

控制 deepflow-agent 资源用量

### CPU 限制 {#global.limits.max_millicpus}

**标签**:

`hot_update`

**FQCN**:

`global.limits.max_millicpus`

Upgrade from old version: `max_millicpus`

**默认值**:
```yaml
global:
  limits:
    max_millicpus: 1000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Logical Milli Cores |
| Range | [1, 100000] |

**详细描述**:

deepflow-agent 使用 cgroups 来限制自身的 CPU 用量，
1 millicpu = 1 millicore = 0.001 core。

### 内存限制 {#global.limits.max_memory}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.limits.max_memory`

Upgrade from old version: `max_memory`

**默认值**:
```yaml
global:
  limits:
    max_memory: 768
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [128, 100000] |

**详细描述**:

deepflow-agent 使用 cgroups 限制自身的 memory 用量。

注意：
- 专属采集器内存不受限制
- 容器采集器内存限制由容器管理工具来实现
- 同集群的容器采集器内存限制需要一致

### 日志每小时回传上限 {#global.limits.max_log_backhaul_rate}

**标签**:

`hot_update`

**FQCN**:

`global.limits.max_log_backhaul_rate`

Upgrade from old version: `log_threshold`

**默认值**:
```yaml
global:
  limits:
    max_log_backhaul_rate: 36000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Lines/Hour |
| Range | [0, 1000000] |

**详细描述**:

用于 deepflow-agent 控制自身运行日志的每小时回传数量，设置为 0 表示不设限制。

### 本地日志文件大小上限 {#global.limits.max_local_log_file_size}

**标签**:

`hot_update`

**FQCN**:

`global.limits.max_local_log_file_size`

Upgrade from old version: `log_file_size`

**默认值**:
```yaml
global:
  limits:
    max_local_log_file_size: 1000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [10, 10000] |

**详细描述**:

用于 deepflow-agent 控制自身运行日志在本地的存储量。

### 本地日志留存时间 {#global.limits.local_log_retention}

**标签**:

`hot_update`

**FQCN**:

`global.limits.local_log_retention`

Upgrade from old version: `log_retention`

**默认值**:
```yaml
global:
  limits:
    local_log_retention: 300d
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10d', '10000d'] |

**详细描述**:

用于 deepflow-agent 控制自身运行日志在本地的留存时长。

### Socket 数量上限 {#global.limits.max_sockets}

**标签**:

`hot_update`

**FQCN**:

`global.limits.max_sockets`

Upgrade from old version: `static_config.max-sockets`

**默认值**:
```yaml
global:
  limits:
    max_sockets: 1024
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | count |
| Range | [16, 4096] |

**详细描述**:

用于控制 deepflow-agent 可以打开的 socket 数量上限。
超过限制时 agent 会重启。

### Socket 数量超限容忍时间 {#global.limits.max_sockets_tolerate_interval}

**标签**:

`hot_update`

**FQCN**:

`global.limits.max_sockets_tolerate_interval`

Upgrade from old version: `static_config.max-sockets-tolerate-interval`

**默认值**:
```yaml
global:
  limits:
    max_sockets_tolerate_interval: 60s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0s', '3600s'] |

**详细描述**:

用于控制 deepflow-agent 在 socket 数量超过上限后，重启前的容忍时间。
只有当 socket 数量持续超过上限达到该时间后才会触发重启。
重启由 guard 模块触发，因此该值小于 guard-interval 时会导致立即重启。

## 告警 {#global.alerts}

### 线程数限制 {#global.alerts.thread_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.alerts.thread_threshold`

Upgrade from old version: `thread_threshold`

**默认值**:
```yaml
global:
  alerts:
    thread_threshold: 500
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 1000] |

**详细描述**:

用于控制 deepflow-agent 创建的线程数量。
- 当线程数量超过该限制值，会触发采集器异常告警。
- 当线程数量超过该限制值的2倍，会触发采集器重启。

### 进程数限制 {#global.alerts.process_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.alerts.process_threshold`

Upgrade from old version: `process_threshold`

**默认值**:
```yaml
global:
  alerts:
    process_threshold: 10
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 100] |

**详细描述**:

用于控制名称为`deepflow-agent`的进程数量。
若当前系统中名为`deepflow-agent`的进程数达到该限制值，则之后名为`deepflow-agent`的进程将会启动失败。

### Core File 检查 {#global.alerts.check_core_file_disabled}

**标签**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`global.alerts.check_core_file_disabled`

Upgrade from old version: `static_config.check-core-file-disabled`

**默认值**:
```yaml
global:
  alerts:
    check_core_file_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当主机存在无效的 NFS 文件系统，或者 Docker 正在运行时，
检查 core 文件时可能会导致程序挂起。
因此，core 文件检查提供了一个开关，以防止进程挂起。参考链接：
- [https://serverfault.com/questions/367438/ls-hangs-for-a-certain-directory](https://serverfault.com/questions/367438/ls-hangs-for-a-certain-directory)
- [https://unix.stackexchange.com/questions/495854/processes-hanging-when-trying-to-access-a-file](https://unix.stackexchange.com/questions/495854/processes-hanging-when-trying-to-access-a-file)

## 熔断机制 {#global.circuit_breakers}

控制 deepflow-agent 在一定的环境条件下停止运行或停止部分功能。

### 系统空闲内存百分比 {#global.circuit_breakers.sys_memory_percentage}

计算公式：`(free_memory / total_memory) * 100%`

#### 触发阈值 {#global.circuit_breakers.sys_memory_percentage.trigger_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.sys_memory_percentage.trigger_threshold`

Upgrade from old version: `sys_free_memory_limit`

**默认值**:
```yaml
global:
  circuit_breakers:
    sys_memory_percentage:
      trigger_threshold: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | % |
| Range | [0, 100] |

**详细描述**:

设置为 0 表示不检查系统内存比率。
观测内存比率是由 `global.circuit_breakers.sys_memory_percentage.metric` 决定.
1. 当系统`观测内存比率`低于 `trigger_threshold` * 70% 时，
   采集器将自动重启。
2. 当系统`观测内存比率`低于 `trigger_threshold` 但高于 70% 时，
   采集器设置为 `FREE_MEM_EXCEEDED` 的异常状态，并上报采集器异常告警。
3. 当系统`观测内存比率`持续高于 `trigger_threshold` * 110% 时，
   采集器将从异常状态恢复。

#### 观测指标 {#global.circuit_breakers.sys_memory_percentage.metric}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.sys_memory_percentage.metric`

Upgrade from old version: `sys_free_memory_metric`

**默认值**:
```yaml
global:
  circuit_breakers:
    sys_memory_percentage:
      metric: free
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| free | |
| available | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 观测该内存指标的百分比

### 相对系统负载 {#global.circuit_breakers.relative_sys_load}

计算公式: `system_load / total_cpu_cores`

#### 触发阈值 {#global.circuit_breakers.relative_sys_load.trigger_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.relative_sys_load.trigger_threshold`

Upgrade from old version: `system_load_circuit_breaker_threshold`

**默认值**:
```yaml
global:
  circuit_breakers:
    relative_sys_load:
      trigger_threshold: 1.0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | float |
| Range | [0, 10] |

**详细描述**:

当`相对系统负载`（load 除以 CPU 核数）高于此阈值时，采集器自动停止运行。
设置该值或 `recovery_threshold` 为 0 时，该特性不生效。

#### 恢复阈值 {#global.circuit_breakers.relative_sys_load.recovery_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.relative_sys_load.recovery_threshold`

Upgrade from old version: `system_load_circuit_breaker_recover`

**默认值**:
```yaml
global:
  circuit_breakers:
    relative_sys_load:
      recovery_threshold: 0.9
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | float |
| Range | [0, 10] |

**详细描述**:

在采集器处于停止状态后，当`相对系统负载`（load 除以 CPU 核数）连续 5 分钟低于此阈值时，
采集器自动从停止状态恢复运行。
设置该值或 `trigger_threshold` 为 0 时，该特性不生效。

#### 观测指标 {#global.circuit_breakers.relative_sys_load.metric}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.relative_sys_load.metric`

Upgrade from old version: `system_load_circuit_breaker_metric`

**默认值**:
```yaml
global:
  circuit_breakers:
    relative_sys_load:
      metric: load15
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| load1 | |
| load5 | |
| load15 | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 默认每 10 秒监控一次所设定的系统负载指标项。

### 发送吞吐 {#global.circuit_breakers.tx_throughput}

#### 触发阈值 {#global.circuit_breakers.tx_throughput.trigger_threshold}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`global.circuit_breakers.tx_throughput.trigger_threshold`

Upgrade from old version: `max_tx_bandwidth`

**默认值**:
```yaml
global:
  circuit_breakers:
    tx_throughput:
      trigger_threshold: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Mbps |
| Range | [0, 100000] |

**详细描述**:

如果流量分发所用网络接口的出方向吞吐量达到或超出此阈值，deepflow-agent 停止流量分发；
如果该网络接口的出方向吞吐量连续 5 个监控周期低于`(trigger_threshold -
outputs.npb.max_tx_throughput)*90%`，deepflow-agent 恢复流量分发。

注意：
1. 取值为 0 时，该特性不生效；
2. 若取非 0 值，必须大于 `outputs.npb.max_tx_throughput`。

#### 吞吐监控间隔 {#global.circuit_breakers.tx_throughput.throughput_monitoring_interval}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`global.circuit_breakers.tx_throughput.throughput_monitoring_interval`

Upgrade from old version: `bandwidth_probe_interval`

**默认值**:
```yaml
global:
  circuit_breakers:
    tx_throughput:
      throughput_monitoring_interval: 10s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '60s'] |

**详细描述**:

deepflow-agent 对流量分发所使用网络接口的出方向吞吐量指标的监控周期。

### 空闲磁盘 {#global.circuit_breakers.free_disk}

#### 百分比触发阈值 {#global.circuit_breakers.free_disk.percentage_trigger_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.free_disk.percentage_trigger_threshold`

**默认值**:
```yaml
global:
  circuit_breakers:
    free_disk:
      percentage_trigger_threshold: 15
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | % |
| Range | [0, 100] |

**详细描述**:

仅当采集器运行在非容器环境中时该配置有效。配置为 0 表示禁用该阈值。
观测磁盘为`global.circuit_breakers.free_disk.directories`目录所在磁盘。
1. 当系统`空闲磁盘比率`低于`该阈值`时，采集器进入熔断禁用状态，
   并设置`磁盘空闲空间触发熔断`异常状态，同时上报采集器异常告警。
2. 当系统`空闲磁盘比率`高于`该阈值 * 110%` 时，采集器从异常状态恢复。

#### 绝对值触发阈值 {#global.circuit_breakers.free_disk.absolute_trigger_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.free_disk.absolute_trigger_threshold`

**默认值**:
```yaml
global:
  circuit_breakers:
    free_disk:
      absolute_trigger_threshold: 10
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | GB |
| Range | [0, 100000] |

**详细描述**:

仅当采集器运行在非容器环境中时该配置有效。配置为 0 表示禁用该阈值。
观测磁盘为`global.circuit_breakers.free_disk.directories`目录所在磁盘。
1. 当系统`空闲磁盘大小`低于`该阈值`时，采集器进入熔断禁用状态，
   并设置`磁盘空闲空间触发熔断`异常状态，同时上报采集器异常告警。
2. 当系统`空闲磁盘大小`高于`该阈值 * 110%` 时，采集器从异常状态恢复。

#### 观测目录 {#global.circuit_breakers.free_disk.directories}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.free_disk.directories`

**默认值**:
```yaml
global:
  circuit_breakers:
    free_disk:
      directories:
      - /
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

观测目录所在磁盘的空间。
对于`windows`操作系统，默认值则是`c:\`

## 调优 {#global.tunning}

对 deepflow-agent 的运行进行调优。

### CPU 亲和性 {#global.tunning.cpu_affinity}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.tunning.cpu_affinity`

Upgrade from old version: `static_config.cpu-affinity`

**默认值**:
```yaml
global:
  tunning:
    cpu_affinity: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 65536] |

**详细描述**:

操作系统尽可能使用指定 ID 的 CPU 核运行 deepflow-agent 进程。无效的 ID 将被忽略。当前仅对
dispatcher 线程生效。举例：
```yaml
global:
  tunning:
    cpu_affinity: [1, 3, 5, 7, 9]
```

### 进程调度优先级 {#global.tunning.process_scheduling_priority}

**标签**:

`hot_update`

**FQCN**:

`global.tunning.process_scheduling_priority`

Upgrade from old version: `static_config.process-scheduling-priority`

**默认值**:
```yaml
global:
  tunning:
    process_scheduling_priority: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [-20, 19] |

**详细描述**:

控制 deepflow-agent 进程的调度优先级。数值越小，调度优先级越高；数值越大，调度优先级越低。

### 闲置内存修剪 {#global.tunning.idle_memory_trimming}

**标签**:

`hot_update`

**FQCN**:

`global.tunning.idle_memory_trimming`

Upgrade from old version: `static_config.memory-trim-disabled`

**默认值**:
```yaml
global:
  tunning:
    idle_memory_trimming: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启闲置内存修剪特性，将降低 agent 内存使用量，但可能会损失 agent 处理性能。

### 禁用 swap 内存 {#global.tunning.swap_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.tunning.swap_disabled`

**默认值**:
```yaml
global:
  tunning:
    swap_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

注意禁用 swap 内存需要 root 和 CAP_IPC_LOCK 权限，禁用 swap 内存后性能也许会提升并且CPU使用率会降低,
但是内存会升高。

### Page Cache 回收百分比 {#global.tunning.page_cache_reclaim_percentage}

**标签**:

`hot_update`

**FQCN**:

`global.tunning.page_cache_reclaim_percentage`

Upgrade from old version: `static_config.page-cache-reclaim-percentage`

**默认值**:
```yaml
global:
  tunning:
    page_cache_reclaim_percentage: 100
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 100] |

**详细描述**:

当文件页缓存和 cgroup 内存限制的百分比超过此阈值时，agent 将清空文件页缓存。
Cgroup 的内存使用量包括匿名内存和文件页缓存。在某些情况下，仅仅是文件页缓存就可能导致
cgroup 因为内存不足杀死 agent 进程。为了避免这种情况，agent 将定期强制清空文件页缓存，
且由于 agent 的文件 I/O 量不大，这不太可能对 agent 的性能造成影响，但同一 cgroup 下的其他
进程可能会受到影响。不建议设置很小的值。
注意：
- 该特性仅支持 cgroups v1。
- 如果 agent 的 memory cgroup 路径是 “/”，该特性不生效。
- 回收的最小间隔是 1 分钟。

### 资源监控间隔 {#global.tunning.resource_monitoring_interval}

**标签**:

`hot_update`

**FQCN**:

`global.tunning.resource_monitoring_interval`

Upgrade from old version: `static_config.guard-interval`

**默认值**:
```yaml
global:
  tunning:
    resource_monitoring_interval: 10s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '3600s'] |

**详细描述**:

deepflow-agent 将以配置的时间周期监控如下资源：
1. 系统空闲内存
2. 系统负载
3. agent 的线程数量（通过读取 /proc 目录下的文件信息获取）
4. agent 的日志数量和日志大小
5. agent 的内存用量

## NTP 时钟同步 {#global.ntp}

此同步机制获取的时间仅供 deepflow-agent 进程内部使用，不影响主机时间。

### Enabled {#global.ntp.enabled}

**标签**:

`hot_update`

**FQCN**:

`global.ntp.enabled`

Upgrade from old version: `ntp_enabled`

**默认值**:
```yaml
global:
  ntp:
    enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

deepflow-agent 是否向 deepflow-server 做 NTP 同步的开关。

注意：开启 NTP 前控制器需要先开启 NTP 服务，直到完成同步时间后采集器才会继续运行。

### 最大时钟偏差 {#global.ntp.max_drift}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.ntp.max_drift`

Upgrade from old version: `static_config.ntp-max-interval`

**默认值**:
```yaml
global:
  ntp:
    max_drift: 300s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '365d'] |

**详细描述**:

当 deepflow-agent 与 deepflow-server 之间的时间偏移大于此设置值时，agent 会自动重启。

### 最小时钟偏差 {#global.ntp.min_drift}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.ntp.min_drift`

Upgrade from old version: `static_config.ntp-min-interval`

**默认值**:
```yaml
global:
  ntp:
    min_drift: 10s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '365d'] |

**详细描述**:

当 deepflow-agent 与 deepflow-server 之间的时间偏移大于此设置值时，对 agent 的
时间戳进行纠正。

## 通信 {#global.communication}

配置 deepflow-agent 的通信参数。

### 主动请求间隔 {#global.communication.proactive_request_interval}

**标签**:

`hot_update`

**FQCN**:

`global.communication.proactive_request_interval`

Upgrade from old version: `sync_interval`

**默认值**:
```yaml
global:
  communication:
    proactive_request_interval: 60s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '3600s'] |

**详细描述**:

deepflow-agent 以设置的时间间隔周期性向 deepflow-server 请求配置数据和标签信息。

### 最大逃逸时长 {#global.communication.max_escape_duration}

**标签**:

`hot_update`

**FQCN**:

`global.communication.max_escape_duration`

Upgrade from old version: `max_escape_seconds`

**默认值**:
```yaml
global:
  communication:
    max_escape_duration: 3600s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['600s', '30d'] |

**详细描述**:

`最大逃逸时长`是指 deepflow-agent 与 deepflow-server 失联后，自主运行的最长
时间；超过该时长后，仍未与 server 恢复联系，agent 自动进入 disabled 状态。

### Controller IP 地址 {#global.communication.proxy_controller_ip}

**标签**:

`hot_update`

**FQCN**:

`global.communication.proxy_controller_ip`

Upgrade from old version: `proxy_controller_ip`

**默认值**:
```yaml
global:
  communication:
    proxy_controller_ip: 127.0.0.1
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | ip |

**详细描述**:

用于设置 deepflow-agent 与 server 通信的控制面通信 IP；如果不设置本
参数，server 下发自己的节点 IP 作为 server 端控制面通信IP。
该参数通常用于 server 端使用负载均衡或虚 IP 对外提供服务的场景。

### Controller 端口号 {#global.communication.proxy_controller_port}

**标签**:

`hot_update`

**FQCN**:

`global.communication.proxy_controller_port`

Upgrade from old version: `proxy_controller_port`

**默认值**:
```yaml
global:
  communication:
    proxy_controller_port: 30035
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

用于设置 deepflow-server 向 deepflow-agent 下发的 server 端控制面通信端口。

### Ingester IP 地址 {#global.communication.ingester_ip}

**标签**:

`hot_update`

**FQCN**:

`global.communication.ingester_ip`

Upgrade from old version: `analyzer_ip`

**默认值**:
```yaml
global:
  communication:
    ingester_ip: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | ip |

**详细描述**:

用于设置 deepflow-server 向 deepflow-agent 下发的 server 端数据面通信 IP。

### Ingester 端口号 {#global.communication.ingester_port}

**标签**:

`hot_update`

**FQCN**:

`global.communication.ingester_port`

Upgrade from old version: `analyzer_port`

**默认值**:
```yaml
global:
  communication:
    ingester_port: 30033
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

用于设置 deepflow-server 向 deepflow-agent 下发的 server 端数据面通信端口。

### gRPC Socket 缓冲区大小 {#global.communication.grpc_buffer_size}

**标签**:

`hot_update`
<mark>deprecated</mark>

**FQCN**:

`global.communication.grpc_buffer_size`

Upgrade from old version: `static_config.grpc-buffer-size`

**默认值**:
```yaml
global:
  communication:
    grpc_buffer_size: 5
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [5, 1024] |

**详细描述**:

设置 deepflow-agent 的 gRPC socket 缓冲区大小。

### 发送到 Ingester 的最大流量 {#global.communication.max_throughput_to_ingester}

**标签**:

`hot_update`

**FQCN**:

`global.communication.max_throughput_to_ingester`

**默认值**:
```yaml
global:
  communication:
    max_throughput_to_ingester: 100
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Mbps |
| Range | [0, 10000] |

**详细描述**:

向 Server 端 Ingester 模块发送可观测性数据的最大允许流量,
超限行为参考 `ingester_traffic_overflow_action` 配置描述。
配置为 0 表示不限速。

### Ingester 流量超限的动作 {#global.communication.ingester_traffic_overflow_action}

**标签**:

`hot_update`

**FQCN**:

`global.communication.ingester_traffic_overflow_action`

**默认值**:
```yaml
global:
  communication:
    ingester_traffic_overflow_action: WAIT
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| WAIT | |
| DROP | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

Ingester 流量超限的动作
- WAIT：暂停发送，数据缓存到队列，等待下次发送。
- DROP：直接丢弃数据，并触发 Agent `数据流量达到限速`异常。

### 请求 NAT IP 地址 {#global.communication.request_via_nat_ip}

**标签**:

`hot_update`

**FQCN**:

`global.communication.request_via_nat_ip`

Upgrade from old version: `nat_ip_enabled`

**默认值**:
```yaml
global:
  communication:
    request_via_nat_ip: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当 deepflow-agent 使用外部 IP 地址访问 deepflow-server 时，
例如，当 deepflow-server 位于 NAT 网关后，或 deepflow-server 所在的主机有多个
节点 IP 地址，不同的 deepflow-agent 需要访问不同的节点 IP 地址时，可以为每个
deepflow-server 地址设置一个额外的 NAT IP，并将本参数设置为 `true`。

## 自监控 {#global.self_monitoring}

配置 deepflow-agent 自身诊断相关的参数。

### 日志 {#global.self_monitoring.log}

deepflow-agent 自身日志的相关配置参数。

#### 日志等级 {#global.self_monitoring.log.log_level}

**标签**:

`hot_update`

**FQCN**:

`global.self_monitoring.log.log_level`

Upgrade from old version: `log_level`

**默认值**:
```yaml
global:
  self_monitoring:
    log:
      log_level: INFO
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| DEBUG | |
| INFO | |
| WARN | |
| ERROR | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 运行日志输出等级。

也可以通过高级配置指定特定模块的日志等级，格式如下：

```
<log_level_spec> ::= single_log_level_spec[{,single_log_level_spec}][/<text_filter>]
<single_log_level_spec> ::= <path_to_module>|<log_level>|<path_to_module>=<log_level>
<text_filter> ::= <regex>
```

例如：

```
log_level: info,deepflow_agent::rpc::session=debug
```

将设置所有模块的日志等级为 INFO，并将 rpc::session 模块的日志等级设置为 DEBUG。

#### 日志文件 {#global.self_monitoring.log.log_file}

**标签**:

`hot_update`

**FQCN**:

`global.self_monitoring.log.log_file`

Upgrade from old version: `static_config.log-file`

**默认值**:
```yaml
global:
  self_monitoring:
    log:
      log_file: /var/log/deepflow-agent/deepflow-agent.log
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 运行日志的写入位置。

#### 启用日志回传 {#global.self_monitoring.log.log_backhaul_enabled}

**标签**:

`hot_update`

**FQCN**:

`global.self_monitoring.log.log_backhaul_enabled`

Upgrade from old version: `rsyslog_enabled`

**默认值**:
```yaml
global:
  self_monitoring:
    log:
      log_backhaul_enabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后，deepflow-agent 将向 deepflow-server 回传运行日志。

### 持续剖析 {#global.self_monitoring.profile}

deepflow-agent 自身持续剖析数据配置参数

#### Enabled {#global.self_monitoring.profile.enabled}

**标签**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`global.self_monitoring.profile.enabled`

Upgrade from old version: `static_config.profiler`

**默认值**:
```yaml
global:
  self_monitoring:
    profile:
      enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

该参数仅对 deepflow-trident 有效，对 deepflow-agent 无效。
开启后，支持对 Trident 持续剖析。

### 诊断 {#global.self_monitoring.debug}

deepflow-agent 的诊断功能配置参数

#### Enabled {#global.self_monitoring.debug.enabled}

**标签**:

`hot_update`

**FQCN**:

`global.self_monitoring.debug.enabled`

Upgrade from old version: `debug_enabled`

**默认值**:
```yaml
global:
  self_monitoring:
    debug:
      enabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

禁用 / 启用 deepflow-agent 的诊断功能。

#### 本地 UDP 端口号 {#global.self_monitoring.debug.local_udp_port}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.self_monitoring.debug.local_udp_port`

Upgrade from old version: `static_config.debug-listen-port`

**默认值**:
```yaml
global:
  self_monitoring:
    debug:
      local_udp_port: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 65535] |

**详细描述**:

该参数仅对 deepflow-trident 有效，对 deepflow-agent 无效。用于配置
trident 用于诊断的 UDP 监听端口，默认值为 `0` ，表示使用随机的端口。

#### 启用调试指标 {#global.self_monitoring.debug.debug_metrics_enabled}

**标签**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`global.self_monitoring.debug.debug_metrics_enabled`

Upgrade from old version: `static_config.enable-debug-stats`

**默认值**:
```yaml
global:
  self_monitoring:
    debug:
      debug_metrics_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

该参数仅对 deepflow-trident 有效，对 deepflow-agent 无效。

### Interval {#global.self_monitoring.interval}

**标签**:

`hot_update`

**FQCN**:

`global.self_monitoring.interval`

Upgrade from old version: `stats_interval`

**默认值**:
```yaml
global:
  self_monitoring:
    interval: 10s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '3600s'] |

**详细描述**:

statsd 时间间隔。

## 独立运行模式 {#global.standalone_mode}

deepflow-agent 独立运行模式的相关参数

### 最大数据文件大小 {#global.standalone_mode.max_data_file_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.standalone_mode.max_data_file_size`

Upgrade from old version: `static_config.standalone-data-file-size`

**默认值**:
```yaml
global:
  standalone_mode:
    max_data_file_size: 200
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [1, 1000000] |

**详细描述**:

独立运行模式下，单个数据文件的最大值，当文件大小超过最大值时，数据将滚动覆盖。
deepflow-agent 在独立运行模式下不受 deepflow-server 管理/控制，会将采集数据以文件
形式保存在本地磁盘中。目前支持 2 种数据：l4_flow_log 和 l7_flow_log，每种数据分开写入
不同的数据文件，每种数据最多可产生 2 个数据文件。

### 数据文件目录 {#global.standalone_mode.data_file_dir}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.standalone_mode.data_file_dir`

Upgrade from old version: `static_config.standalone-data-file-dir`

**默认值**:
```yaml
global:
  standalone_mode:
    data_file_dir: /var/log/deepflow-agent/
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

数据文件的写入位置。

# 输入 {#inputs}

## 进程 {#inputs.proc}

### Enabled {#inputs.proc.enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.enabled`

Upgrade from old version: `static_config.os-proc-sync-enabled`

**默认值**:
```yaml
inputs:
  proc:
    enabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启此配置后，deepflow-agent 会周期性将 `inputs.proc.process_matcher` 中指定的进程信息上报给 deepflow-server。
同步进程信息后，所有的 eBPF 观测数据都会自动注入`全局进程 ID`（`gprocess_id`）标签。

注意：开启此功能时，需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `proc.gprocess_info`。

该参数仅对`云服务器`（CHOST_VM、CHOST_BM）和`容器`（K8S_VM、K8S_BM）类型的 agent 有效，
在命令行下使用 `deepflow-ctl agent list` 可确定 agent 的具体类型。

### /proc 目录 {#inputs.proc.proc_dir_path}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.proc_dir_path`

Upgrade from old version: `static_config.os-proc-root`

**默认值**:
```yaml
inputs:
  proc:
    proc_dir_path: /proc
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

进程信息同步所用的目录。

### Socket 信息同步间隔 {#inputs.proc.socket_info_sync_interval}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.socket_info_sync_interval`

Upgrade from old version: `static_config.os-proc-socket-sync-interval`

**默认值**:
```yaml
inputs:
  proc:
    socket_info_sync_interval: 0ns
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1h'] |

**详细描述**:

进程 Socket 信息的同步周期。

'0ns' 表示不开启，除 '0ns' 外不要配置小于 `1s` 的值。

注意：开启此功能时，需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `inputs.proc.socket_info_sync_interval`。
另外，也要注意确认 `inputs.proc.enabled` 已配置为 **true**。

### 最小活跃时间 {#inputs.proc.min_lifetime}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.min_lifetime`

Upgrade from old version: `static_config.os-proc-socket-min-lifetime`

**默认值**:
```yaml
inputs:
  proc:
    min_lifetime: 3s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1h'] |

**详细描述**:

如果接口或进程的活跃时间低于该参数值，deepflow-agent 将不上报该接口或进程的信息。

### Tag 提取 {#inputs.proc.tag_extraction}

#### 脚本命令 {#inputs.proc.tag_extraction.script_command}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.tag_extraction.script_command`

Upgrade from old version: `static_config.os-app-tag-exec`

**默认值**:
```yaml
inputs:
  proc:
    tag_extraction:
      script_command: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 每次采集进程信息时，会执行配置的脚本命令，并从标准输出的 yaml 格式
中尝试获取进程的标签字段。yaml 格式的样例如下：
```yaml
- pid: 1
  tags:
  - key: xxx
    value: xxx
- pid: 2
  tags:
  - key: xxx
    value: xxx
```
配置样例:
```yaml
inputs:
  proc:
    tag_extraction:
      script_command: ["cat", "/tmp/tag.yaml"]
```

#### 执行用户名 {#inputs.proc.tag_extraction.exec_username}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.tag_extraction.exec_username`

Upgrade from old version: `static_config.os-app-tag-exec-user`

**默认值**:
```yaml
inputs:
  proc:
    tag_extraction:
      exec_username: deepflow
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 执行 `script_command` 脚本命令的用户名。

### 进程黑名单 {#inputs.proc.process_blacklist}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_blacklist`

**默认值**:
```yaml
inputs:
  proc:
    process_blacklist:
    - sleep
    - sh
    - bash
    - pause
    - runc
    - grep
    - awk
    - sed
    - curl
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

进程匹配器忽略的进程列表。

### 进程匹配器 {#inputs.proc.process_matcher}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher`

Upgrade from old version: `static_config.os-proc-regex`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - enabled_features:
      - ebpf.profile.on_cpu
      - proc.gprocess_info
      match_regex: \bjava( +\S+)* +-jar +(\S*/)*([^ /]+\.jar)
      match_type: cmdline_with_args
      only_in_container: false
      rewrite_name: $3
    - enabled_features:
      - ebpf.profile.on_cpu
      - proc.gprocess_info
      match_regex: \bpython(\S)*( +-\S+)* +(\S*/)*([^ /]+)
      match_type: cmdline_with_args
      only_in_container: false
      rewrite_name: $4
    - enabled_features:
      - ebpf.profile.on_cpu
      - proc.gprocess_info
      match_regex: \b(?:lua|luajit)(\S)*( +-\S+)* +(\S*/)*([^ /]+)
      match_type: cmdline_with_args
      only_in_container: false
      rewrite_name: $5
    - enabled_features:
      - ebpf.profile.on_cpu
      - proc.gprocess_info
      match_regex: \bphp(\d+)?(-fpm|-cli|-cgi)?( +-\S+)* +(\S*/)*([^ /]+\.php)
      match_type: cmdline_with_args
      only_in_container: false
      rewrite_name: $5
    - enabled_features:
      - ebpf.profile.on_cpu
      - proc.gprocess_info
      match_regex: \b(node|nodejs)( +--\S+)* +(\S*/)*([^ /]+\.js)
      match_type: cmdline_with_args
      only_in_container: false
      rewrite_name: $4
    - enabled_features:
      - ebpf.profile.on_cpu
      - proc.gprocess_info
      match_regex: ^deepflow-
      only_in_container: false
    - enabled_features:
      - proc.gprocess_info
      match_regex: .*
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

用于指定为特定进程开启的高级功能列表。

匹配器将自上而下地遍历匹配规则，所以较前的规则将会被优先匹配。
当 match_type 为 parent_process_name 时，匹配器将会递归地查找父进程名且忽略 rewrite_name 选项。
rewrite_name 可定义为正则表达式捕获组索引，或 windows 风格的环境变量。
例如：`$1-py-script-%HOSTNAME%` 中的 $1 将会替换正则表达式捕获到的第一组内容，并替换 HOSTNAME 环境变量。

配置键：
- match_regex: 用于匹配进程的表达式，缺省值为 `""`。
- match_type: 被用于正则表达式匹配的对象，缺省值为 `process_name`，可选项为：
  [process_name, cmdline, cmdline_with_args, parent_process_name, tag]
- ignore: 是否要忽略匹配到的进程，缺省值为 `false`
- rewrite_name: 使用正则替换匹配到的进程名或命令行，缺省值为 `""` 表示不做替换。
- enabled_features: 为匹配到的进程开启的特性列表，可选项如下
  - proc.gprocess_info（注意确认 `inputs.proc.enabled` 已配置为 **true**）
  - proc.golang_symbol_table（注意确认 `inputs.proc.symbol_table.golang_specific.enabled` 已配置为 **true**）
  - proc.socket_list（注意确认 `inputs.proc.socket_info_sync_interval` 已配置为**大于 0 的数字**）
  - ebpf.socket.uprobe.golang（注意确认 `inputs.ebpf.socket.uprobe.golang.enabled` 已配置为 **true**）
  - ebpf.socket.uprobe.tls（注意确认 `inputs.ebpf.socket.uprobe.tls.enabled` 已配置为 **true**）
  - ebpf.profile.on_cpu（注意确认 `inputs.ebpf.profile.on_cpu.disabled` 已配置为 **false**）
  - ebpf.profile.off_cpu（注意确认 `inputs.ebpf.profile.off_cpu.disabled` 已配置为 **false**）
  - ebpf.profile.memory（注意确认 `inputs.ebpf.profile.memory.disabled` 已配置为 **false**）

示例:
```yaml
inputs:
  proc:
    process_matcher:
    - match_regex: python3 (.*)\.py
      match_type: cmdline
      match_languages: []
      match_usernames: []
      only_in_container: true
      only_with_tag: false
      ignore: false
      rewrite_name: $1-py-script
      enabled_features: [ebpf.socket.uprobe.golang, ebpf.profile.on_cpu]
    - match_regex: (?P<PROC_NAME>nginx)
      match_type: process_name
      rewrite_name: ${PROC_NAME}-%HOSTNAME%
    - match_regex: "nginx"
      match_type: parent_process_name
      ignore: true
    - match_regex: .*sleep.*
      match_type: process_name
      ignore: true
    - match_regex: .+ # 可使用冒号连接需要匹配的 tag key 与 value
                      # i.e.: `app:.+` 表示匹配所有具有 `app` tag 的进程
      match_type: tag
```

#### 匹配正则表达式 {#inputs.proc.process_matcher.match_regex}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_regex`

Upgrade from old version: `static_config.os-proc-regex.match-regex`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_regex: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

匹配正则表达式。

#### 匹配类型 {#inputs.proc.process_matcher.match_type}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_type`

Upgrade from old version: `static_config.os-proc-regex.match-type`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_type: process_name
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| process_name | |
| cmdline | |
| cmdline_with_args | |
| parent_process_name | |
| tag | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

匹配类型。

#### 匹配语言 {#inputs.proc.process_matcher.match_languages}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_languages`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_languages: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| java | |
| golang | |
| python | |
| lua | |
| php | |
| nodejs | |
| dotnet | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

默认值 `[]` 匹配所有语言。

#### 匹配用户名 {#inputs.proc.process_matcher.match_usernames}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_usernames`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_usernames: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

默认值 `[]` 匹配所有语言。

#### 仅匹配容器内的进程 {#inputs.proc.process_matcher.only_in_container}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.only_in_container`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - only_in_container: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

默认值 `true` 表示仅匹配容器中的进程。

#### 仅匹配有 Tag 的进程 {#inputs.proc.process_matcher.only_with_tag}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.only_with_tag`

Upgrade from old version: `static_config.os-proc-sync-tagged-only`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - only_with_tag: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

默认值 `false` 表示匹配所有进程。

#### 忽略 {#inputs.proc.process_matcher.ignore}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.ignore`

Upgrade from old version: `static_config.os-proc-regex.action`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - ignore: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

是否忽略匹配的进程。

#### 重命名 {#inputs.proc.process_matcher.rewrite_name}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.rewrite_name`

Upgrade from old version: `static_config.os-proc-regex.rewrite-name`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - rewrite_name: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

匹配后的新名称。

#### 开启功能列表 {#inputs.proc.process_matcher.enabled_features}

**标签**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.enabled_features`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.regex, static_config.ebpf.off-cpu-profile.regex`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - enabled_features: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| proc.gprocess_info | 同步进程资源信息，并为 eBPF 原始观测数据注入所在观测点上的进程标签 |
| proc.golang_symbol_table | 解析 Golang 特有符号表，用于 Golang 进程裁剪了标准符号表时的剖析数据优化 |
| proc.socket_list | 同步进程的活跃 Socket 信息，用于为应用和网络观测数据注入通信双方的进程标签 |
| ebpf.socket.uprobe.golang | 为 Golang 进程开启 eBPF uprobe，用于协程追踪并采集 Golang HTTP2/HTTPS 通信 |
| ebpf.socket.uprobe.tls | 为 TLS 通信开启 eBPF uprobe，用于采集非 Golang 进程的加密通信观测数据 |
| ebpf.profile.on_cpu | 开启 On-CPU 持续剖析功能 |
| ebpf.profile.off_cpu | 开启 Off-CPU 持续剖析功能 |
| ebpf.profile.memory | 开启内存持续剖析功能 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

注意也需要同时开启相关特性的总开关：
- proc.gprocess_info（注意确认 `inputs.proc.enabled` 已配置为 **true**）
- proc.golang_symbol_table（注意确认 `inputs.proc.symbol_table.golang_specific.enabled` 已配置为 **true**）
- proc.socket_list（注意确认 `inputs.proc.socket_info_sync_interval` 已配置为**大于 0 的数字**）
- ebpf.socket.uprobe.golang（注意确认 `inputs.ebpf.socket.uprobe.golang.enabled` 已配置为 **true**）
- ebpf.socket.uprobe.tls（注意确认 `inputs.ebpf.socket.uprobe.tls.enabled` 已配置为 **true**）
- ebpf.profile.on_cpu（注意确认 `inputs.ebpf.profile.on_cpu.disabled` 已配置为 **false**）
- ebpf.profile.off_cpu（注意确认 `inputs.ebpf.profile.off_cpu.disabled` 已配置为 **false**）
- ebpf.profile.memory（注意确认 `inputs.ebpf.profile.memory.disabled` 已配置为 **false**）

### 符号表 {#inputs.proc.symbol_table}

#### Golang 特有 {#inputs.proc.symbol_table.golang_specific}

##### Enabled {#inputs.proc.symbol_table.golang_specific.enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.symbol_table.golang_specific.enabled`

Upgrade from old version: `static_config.ebpf.uprobe-process-name-regexs.golang-symbol`

**默认值**:
```yaml
inputs:
  proc:
    symbol_table:
      golang_specific:
        enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

是否开启 Golang 特有符号表的解析能力。

如果 Golang（版本 >= 1.13 and < 1.18条件下）进程运行时裁切了标准符号
表，开启此开关后 deepflow-agent 将解析生成 Golang-specific 符号表以
完善 eBPF uprobe 数据，实现 Golang 程序的零侵扰调用链追踪。注意：开启
该开关后，eBPF 程序初始化过程可能会持续 10 分钟以上的时间。

配置方法：
- 如果在 deepflow-agent 的运行日志中发现如下 warning：
  ```
  [eBPF] WARNING: func resolve_bin_file() [user/go_tracer.c:558] Go process pid 1946
  [path: /proc/1946/root/usr/local/bin/kube-controller-manager] (version: go1.16). Not find any symbols!
  ```
  以上日志说明存在一个 PID = 1946 的 Golang 进程。
- 确认是否 Golang 进程是否已有符号表:
  - 通过 PID 获取程序可执行文件的目录:
    ```
    # ls -al /proc/1946/exe
    /proc/1946/exe -> /usr/local/bin/kube-controller-manager
    ```
  - 检查目录下是否有符号表：
    ```
    # nm /proc/1946/root/usr/local/bin/kube-controller-manager
    nm: /proc/1946/root/usr/local/bin/kube-controller-manager: no symbols
    ```
- 如果结果中出现 "no symbols"，则说明符号表缺失，需要开启 Golang 程序符号表解析开关.
- deepflow-agent 启动阶段运行日志中出现类似下面的信息，说明 Golang 进程已经被成功 hook。
  ```
  [eBPF] INFO Uprobe [/proc/1946/root/usr/local/bin/kube-controller-manager] pid:1946 go1.16.0
  entry:0x25fca0 size:1952 symname:crypto/tls.(*Conn).Write probe_func:uprobe_go_tls_write_enter rets_count:0
  ```

注意：开启此功能时，需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `proc.golang_symbol_table`。

#### Java {#inputs.proc.symbol_table.java}

##### 刷新延迟时长 {#inputs.proc.symbol_table.java.refresh_defer_duration}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.symbol_table.java.refresh_defer_duration`

Upgrade from old version: `static_config.ebpf.java-symbol-file-refresh-defer-interval`

**默认值**:
```yaml
inputs:
  proc:
    symbol_table:
      java:
        refresh_defer_duration: 60s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['5s', '3600s'] |

**详细描述**:

当 deepflow-agent 在 Java 进程的函数调用栈中发现未能解析的函数名时，将触发进程函数符号表的生成和符号缓存
的更新。当前 Java 符号文件是采用持续更新的方式，该 duration 用于控制推迟使用符号文件更新符号缓存的时间。
原因是由于 Java 使用了 JIT 编译机制，编译符号生成有个预热阶段，为了获取更充足的 Java 符号需要推迟一段时间
来更新 Java 符号的缓存，也可避免由于符号缺失而造成的频繁符号缓存刷新引起大量CPU资源消耗。

##### 符号表文件最大大小 {#inputs.proc.symbol_table.java.max_symbol_file_size}

**标签**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`inputs.proc.symbol_table.java.max_symbol_file_size`

Upgrade from old version: `static_config.ebpf.java-symbol-file-max-space-limit`

**默认值**:
```yaml
inputs:
  proc:
    symbol_table:
      java:
        max_symbol_file_size: 10
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [2, 100] |

**详细描述**:

deepflow-agent 将所有的 Java 符号表文件存放在'/tmp'目录下，该参数用于限制每一个 Java 符号表文件的
大小上限，以避免占用过多的节点磁盘空间。

## cBPF {#inputs.cbpf}

### 通用配置 {#inputs.cbpf.common}

#### Packet 采集模式 {#inputs.cbpf.common.capture_mode}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.common.capture_mode`

Upgrade from old version: `tap_mode`

**默认值**:
```yaml
inputs:
  cbpf:
    common:
      capture_mode: 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | 本地流量 |
| 1 | 虚拟网络镜像 |
| 2 | 物理网络镜像 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

`虚拟网络镜像`模式用于 deepflow-agent 无法直接采集流量的场景，比如：
- k8s 的 macvlan 环境中，从 Node 网口接口采集 POD 流量；
- Hyper-V 环境中，从宿主机的网络接口采集 VM 流量；
- ESXi 环境中，通过 VDS/VSS 的本地 SPAN 采集 VM 流量；
- DPDK 环境中，通过 DPDK ring buffer 采集 VM 流量。

`物理网络镜像`模式（仅企业版支持）用于 deepflow-agent 从物理设备镜像采集流量的场景。

### 使用 AF_PACKET 采集 {#inputs.cbpf.af_packet}

#### 网卡名正则表达式 {#inputs.cbpf.af_packet.interface_regex}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.interface_regex`

Upgrade from old version: `tap_interface_regex`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      interface_regex: ^(tap.*|cali.*|veth.*|eth.*|en[osipx].*|lxc.*|lo|[0-9a-f]+_h)$
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 65535] |

**详细描述**:

需要采集流量的网络接口的正则表达式。

默认配置说明:
```
Localhost:     lo
Common NIC:    eth.*|en[osipx].*
QEMU VM NIC:   tap.*
Flannel:       veth.*
Calico:        cali.*
Cilium         lxc.*
Kube-OVN       [0-9a-f]+_h$
```
未配置时，表示未采集网卡流量

#### 内网络命名空间采集开关 {#inputs.cbpf.af_packet.inner_interface_capture_enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.inner_interface_capture_enabled`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      inner_interface_capture_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

是否采集内网络命名空间流量。
设置为启用会使采集器为每个内网络命名空间创建一个独立的接收引擎线程，
这会导致额外的内存消耗。
默认配置 `inputs.cbpf.af_packet.tunning.ring_blocks` 为 128，
这意味着每个网络命名空间将消耗 128 * 1MB 的内存。
一个有 20 个 POD 的节点将需要 20 * 128 * 1MB = 2.56GB 的内存。
请在启用此功能之前估计内存消耗，启用 `inputs.cbpf.af_packet.tunning.ring_blocks_enabled`
并调整 `inputs.cbpf.af_packet.tunning.ring_blocks` 以减少内存消耗。

#### 内网络命名空间网卡名正则表达式 {#inputs.cbpf.af_packet.inner_interface_regex}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.inner_interface_regex`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      inner_interface_regex: ^eth\d+$
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 65535] |

**详细描述**:

需要采集流量的内网络命名空间网卡的正则表达式。

#### Bond 网卡列表 {#inputs.cbpf.af_packet.bond_interfaces}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.bond_interfaces`

Upgrade from old version: `static_config.tap-interface-bond-groups`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      bond_interfaces: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

同一组内接口的数据包可以聚合在一起，
仅当 `inputs.cbpf.common.capture_mode` 为0时有效。

例子:
```yaml
inputs:
  cbpf:
    af_packet:
      bond_interfaces:
      - slave_interfaces: [eth0, eth1]
      - slave_interfaces: [eth2, eth3]
```

##### Slave 网卡列表 {#inputs.cbpf.af_packet.bond_interfaces.slave_interfaces}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.bond_interfaces.slave_interfaces`

Upgrade from old version: `static_config.tap-interface-bond-groups.tap-interfaces`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      bond_interfaces:
      - slave_interfaces: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

Bond 网卡的从网卡列表。

#### 需要采集的额外网络 Namespace {#inputs.cbpf.af_packet.extra_netns_regex}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.af_packet.extra_netns_regex`

Upgrade from old version: `extra_netns_regex`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      extra_netns_regex: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

除默认网络 namespace 之外，deepflow-agent 还会根据此参数正则匹配额外的网络 namespace，
在匹配命中的网络 namespace 中根据`inputs.cbpf.af_packet.interface_regex`正则匹配网络接口并采集流量。默认
配置 `""` 表示仅采集默认网络 namesapce，不采集额外的网络 namespace 流量。

#### 额外的 BPF 过滤器 {#inputs.cbpf.af_packet.extra_bpf_filter}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.extra_bpf_filter`

Upgrade from old version: `capture_bpf`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      extra_bpf_filter: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 512] |

**详细描述**:

如果不配置该参数，则采集全部流量。BPF 语法详见：[https://biot.com/capstats/bpf.html](https://biot.com/capstats/bpf.html)

#### TAP Interfaces {#inputs.cbpf.af_packet.src_interfaces}

**标签**:

<mark></mark>
<mark>deprecated</mark>

**FQCN**:

`inputs.cbpf.af_packet.src_interfaces`

Upgrade from old version: `static_config.src-interfaces`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      src_interfaces: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

#### 物理网络镜像流量中的 VLAN PCP {#inputs.cbpf.af_packet.vlan_pcp_in_physical_mirror_traffic}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.af_packet.vlan_pcp_in_physical_mirror_traffic`

Upgrade from old version: `static_config.mirror-traffic-pcp`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      vlan_pcp_in_physical_mirror_traffic: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 9] |

**详细描述**:

- 当此配置值小于等于 7 时，仅当 VLAN PCP 与该值匹配时，从 VLAN tag 中计算 TAP。
- 当此配置值为 8 时，从外层 VLAN tag 中计算 TAP，
- 当此配置值为 9 时，从内层 VLAN tag 中计算 TAP。

#### 禁用 BPF 过滤 {#inputs.cbpf.af_packet.bpf_filter_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.bpf_filter_disabled`

Upgrade from old version: `static_config.bpf-disabled`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      bpf_filter_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

此开关用于对特定 Linux 内核版本 BPF 功能诊断，打开此开关后 deepflow-agent 将不启用 Linux
内核的 BPF 包过滤能力，而是获取全流量的数据包之后由采集器程序进行过滤。注意，打开此开关将明显
增加 deepflow-agent 的资源消耗。

#### 跳过 NPB BPF {#inputs.cbpf.af_packet.skip_npb_bpf}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.skip_npb_bpf`

Upgrade from old version: `static_config.skip-npb-bpf`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      skip_npb_bpf: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

如果采集网卡中有 ERSPAN 流量但是没有分发流量，开启这个开关来采集 ERSPAN 流量。

#### 调优 {#inputs.cbpf.af_packet.tunning}

##### Socket 版本 {#inputs.cbpf.af_packet.tunning.socket_version}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.tunning.socket_version`

Upgrade from old version: `capture_socket_type`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        socket_version: 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | 自适应 |
| 2 | AF_PACKET V2 |
| 3 | AF_PACKET V3 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

deepflow-agent 所在的 Linux 操作系统的 AF_PACKET socket 版本号。

##### 使能 Ring Blocks 配置 {#inputs.cbpf.af_packet.tunning.ring_blocks_enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.ring_blocks_enabled`

Upgrade from old version: `static_config.afpacket-blocks-enabled`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        ring_blocks_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当 `inputs.cbpf.common.capture_mode` 为 `本地流量`或`虚拟网络镜像`模式，需开启此开关，
并配置 `inputs.cbpf.af_packet.tunning.ring_blocks` 参数。

##### Ring Blocks {#inputs.cbpf.af_packet.tunning.ring_blocks}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.ring_blocks`

Upgrade from old version: `static_config.afpacket-blocks`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        ring_blocks: 128
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8, 1000000] |

**详细描述**:

配置此参数后，deepflow-agent 将分配指定数量的 block 用于 AF_PACKET，每个 block 的
大小固定为 1 MByte。

##### Packet Fanout 路数 {#inputs.cbpf.af_packet.tunning.packet_fanout_count}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.packet_fanout_count`

Upgrade from old version: `static_config.local-dispatcher-count`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        packet_fanout_count: 1
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 64] |

**详细描述**:

当此配置值大于 1 时，deepflow-agent 将开启多个 dispatcher 线程，并把数据包分散到多个处理
线程并行处理，弹性扩展 dispatcher 以优化网络应用的处理性能。增大此配置可以降低
多核服务器的操作系统软中断数量，但会消耗更多的 CPU 和内存。

注意：
- 参数仅在`inputs.cbpf.common.capture_mode`为 `本地流量`，且`inputs.cbpf.af_packet.extra_netns_regex`为空时有效。
- 当`self.inputs.cbpf.special_network.dpdk.source`为`eBPF`时，这个配置值会被强制置为`self.inputs.ebpf.tunning.userspace_worker_threads`

##### Packet Fanout 模式 {#inputs.cbpf.af_packet.tunning.packet_fanout_mode}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.packet_fanout_mode`

Upgrade from old version: `static_config.packet-fanout-mode`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        packet_fanout_mode: 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | PACKET_FANOUT_HASH |
| 1 | PACKET_FANOUT_LB |
| 2 | PACKET_FANOUT_CPU |
| 3 | PACKET_FANOUT_ROLLOVER |
| 4 | PACKET_FANOUT_RND |
| 5 | PACKET_FANOUT_QM |
| 6 | PACKET_FANOUT_CBPF |
| 7 | PACKET_FANOUT_EBPF |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

数据包 Fanout 的算法/模式。参考：
- [https://github.com/torvalds/linux/blob/afcd48134c58d6af45fb3fdb648f1260b20f2326/include/uapi/linux/if_packet.h#L71](https://github.com/torvalds/linux/blob/afcd48134c58d6af45fb3fdb648f1260b20f2326/include/uapi/linux/if_packet.h#L71)
- [https://www.stackpath.com/blog/bpf-hook-points-part-1/](https://github.com/torvalds/linux/blob/afcd48134c58d6af45fb3fdb648f1260b20f2326/include/uapi/linux/if_packet.h#L71)

##### 开启网卡混杂模式 {#inputs.cbpf.af_packet.tunning.interface_promisc_enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.interface_promisc_enabled`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        interface_promisc_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

如下场景需要开启混杂模式：
- `inputs.cbpf.common.capture_mode` 等于`虚拟网络镜像`或`物理网络镜像`
- `inputs.cbpf.common.capture_mode` 等于`本地流量`并且无法采集到虚拟机的流量
注意：网卡开启混杂模式后会采集更多的流量导致性能降低。

### 特殊网络 {#inputs.cbpf.special_network}

#### DPDK {#inputs.cbpf.special_network.dpdk}

##### 数据源 {#inputs.cbpf.special_network.dpdk.source}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.dpdk.source`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      dpdk:
        source: None
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| None | |
| eBPF | |
| pdump | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

目前支持两种采集 DPDK 流量的方式，包括：
- pdump: 详情见 [https://dpdk-docs.readthedocs.io/en/latest/prog_guide/multi_proc_support.html](https://dpdk-docs.readthedocs.io/en/latest/prog_guide/multi_proc_support.html)
- eBPF: 使用 eBPF Uprobe 的方式获取 DPDK 流量，同时需要配置 `inputs.ebpf.socket.uprobe.dpdk`

##### 乱序重排缓存时间窗口大小 {#inputs.cbpf.special_network.dpdk.reorder_cache_window_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.special_network.dpdk.reorder_cache_window_size`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      dpdk:
        reorder_cache_window_size: 60ms
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['60ms', '100ms'] |

**详细描述**:

当 `inputs.cbpf.special_network.dpdk.source` 为 eBPF 时该配置生效，时间窗口变大会导致 agent 占用更多的内存。

#### Libpcap {#inputs.cbpf.special_network.libpcap}

##### Enabled {#inputs.cbpf.special_network.libpcap.enabled}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.libpcap.enabled`

Upgrade from old version: `static_config.libpcap-enabled`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      libpcap:
        enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

libpcap 的启动开关，该参数在 Windows 系统中默认开启，在 Linux 系统中默认关闭。libcap 在 Windows
和 Linux 系统中均支持，但在多接口的环境中流量采集性能较低。

#### vHost User {#inputs.cbpf.special_network.vhost_user}

##### vHost Socket Path {#inputs.cbpf.special_network.vhost_user.vhost_socket_path}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.vhost_user.vhost_socket_path`

Upgrade from old version: `static_config.vhost-socket-path`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      vhost_user:
        vhost_socket_path: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

支持在 Linux 环境中以虚拟网络镜像模式运行。

#### 物理交换机 {#inputs.cbpf.special_network.physical_switch}

##### sFlow 接收端口号 {#inputs.cbpf.special_network.physical_switch.sflow_ports}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.physical_switch.sflow_ports`

Upgrade from old version: `static_config.xflow-collector.sflow-ports`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      physical_switch:
        sflow_ports: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

配置 sFlow 的接收端口号，默认值`[]`表示不采集 sFlow 数据。通常 sFlow 使用 6343 端口。
注意，该特性仅对企业版的 Trident 有效。

##### NetFlow 接收端口号 {#inputs.cbpf.special_network.physical_switch.netflow_ports}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.physical_switch.netflow_ports`

Upgrade from old version: `static_config.xflow-collector.netflow-ports`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      physical_switch:
        netflow_ports: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

配置 NetFlow 的接收端口号，默认值`[]`表示不采集 NetFlow 数据。通常 sFlow 使用 2055 端口。
注意，该特性仅对企业版的 Trident 有效，且目前仅支持 NetFlow v5 协议。

### 调优 {#inputs.cbpf.tunning}

#### 启用 Dispatcher 队列 {#inputs.cbpf.tunning.dispatcher_queue_enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.tunning.dispatcher_queue_enabled`

Upgrade from old version: `static_config.dispatcher-queue`

**默认值**:
```yaml
inputs:
  cbpf:
    tunning:
      dispatcher_queue_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当 `inputs.cbpf.common.capture_mode` 为`本地流量`或`虚拟网络镜像`时该配置生效。

对所有流量采集方式都可用。

#### 最大采集包长 {#inputs.cbpf.tunning.max_capture_packet_size}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.tunning.max_capture_packet_size`

Upgrade from old version: `capture_packet_size`

**默认值**:
```yaml
inputs:
  cbpf:
    tunning:
      max_capture_packet_size: 65535
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [128, 65535] |

**详细描述**:

该参数配置对 DPDK 环境无效。

#### 裸包缓冲区 Block 大小 {#inputs.cbpf.tunning.raw_packet_buffer_block_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.tunning.raw_packet_buffer_block_size`

Upgrade from old version: `static_config.analyzer-raw-packet-block-size`

**默认值**:
```yaml
inputs:
  cbpf:
    tunning:
      raw_packet_buffer_block_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 16000000] |

**详细描述**:

Analyzer 模式下采集到的包进入队列前需要分配内存暂存。为避免每个包进行内存申请，每次开辟
raw_packet_buffer_block_size 大小的内存块给数个包使用。
更大的配置可以减少内存分配，但会延迟内存释放。
该配置对以下采集模式(`inputs.cbpf.common.capture_mode`)生效：
- analyzer 模式
- local 模式，且 `inputs.cbpf.af_packet.inner_interface_capture_enabled` = true
- local 模式，且 `inputs.cbpf.tunning.dispatcher_queue_enabled` = true
- mirror 模式，且 `inputs.cbpf.tunning.dispatcher_queue_enabled` = true

#### 裸包队列大小 {#inputs.cbpf.tunning.raw_packet_queue_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.tunning.raw_packet_queue_size`

Upgrade from old version: `static_config.analyzer-queue-size`

**默认值**:
```yaml
inputs:
  cbpf:
    tunning:
      raw_packet_queue_size: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

以下队列的长度（仅在 `inputs.cbpf.common.capture_mode` = `物理网络镜像`时有效）：
- 0.1-bytes-to-parse
- 0.2-packet-to-flowgenerator
- 0.3-packet-to-pipeline

#### 最大采集 PPS {#inputs.cbpf.tunning.max_capture_pps}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.tunning.max_capture_pps`

Upgrade from old version: `max_collect_pps`

**默认值**:
```yaml
inputs:
  cbpf:
    tunning:
      max_capture_pps: 1048576
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | pps |
| Range | [1, 10000000] |

**详细描述**:

deepflow-agent 采集数据包的速率上限。

### 预处理 {#inputs.cbpf.preprocess}

#### 隧道解封装协议 {#inputs.cbpf.preprocess.tunnel_decap_protocols}

**标签**:

`hot_update`

**FQCN**:

`inputs.cbpf.preprocess.tunnel_decap_protocols`

Upgrade from old version: `decap_type`

**默认值**:
```yaml
inputs:
  cbpf:
    preprocess:
      tunnel_decap_protocols:
      - 1
      - 2
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 1 | VXLAN |
| 2 | IPIP |
| 3 | GRE |
| 4 | Geneve |
| 5 | VXLAN-NSH |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

deepflow-agent 需要对数据包解封装的隧道协议，仅企业版本支持解析 GRE 和 VXLAN-NSH。

#### 隧道头剥离协议 {#inputs.cbpf.preprocess.tunnel_trim_protocols}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.preprocess.tunnel_trim_protocols`

Upgrade from old version: `static_config.trim-tunnel-types`

**默认值**:
```yaml
inputs:
  cbpf:
    preprocess:
      tunnel_trim_protocols: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| ERSPAN | |
| VXLAN | |
| TEB | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

流量镜像（虚拟或物理）模式下，deepflow-agent 需要剥离的隧道头协议类型。
仅企业版支持解析 ERSPAN 和 TEB。

#### TCP分段重组端口 {#inputs.cbpf.preprocess.packet_segmentation_reassembly}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.preprocess.packet_segmentation_reassembly`

Upgrade from old version: `static_config.packet-segmentation-reassembly`

**默认值**:
```yaml
inputs:
  cbpf:
    preprocess:
      packet_segmentation_reassembly: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

对指定端口的流，相邻的两个TCP分段 Packet 聚合在一起解析应用日志

### 物理网络流量镜像 {#inputs.cbpf.physical_mirror}

#### 默认采集网络类型 {#inputs.cbpf.physical_mirror.default_capture_network_type}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.physical_mirror.default_capture_network_type`

Upgrade from old version: `static_config.default-tap-type`

**默认值**:
```yaml
inputs:
  cbpf:
    physical_mirror:
      default_capture_network_type: 3
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 3 | 云网络 |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

在 `inputs.cbpf.common.capture_mode` 为`物理网络镜像`模式下，deepflow-agent 通过镜像流量的外层 VLAN 标签识别并标记采集数据的
TAP(Traffic Access Point)值。当流量外层 VLAN 标签没有对应的 TAP 值，或 VLAN pcp 值与
`inputs.cbpf.af_packet.vlan_pcp_in_physical_mirror_traffic` 的配置不一致时，deepflow-agent 使用本参数值
标记数据的 TAP 值。

#### 禁用 Packet 去重 {#inputs.cbpf.physical_mirror.packet_dedup_disabled}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.physical_mirror.packet_dedup_disabled`

Upgrade from old version: `static_config.analyzer-dedup-disabled`

**默认值**:
```yaml
inputs:
  cbpf:
    physical_mirror:
      packet_dedup_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当 `inputs.cbpf.common.capture_mode` 为`物理网络镜像`模式, 该参数配置为 `true` 时，deepflow-agent 将不对数据包做去重处理。

#### 专有云网关流量 {#inputs.cbpf.physical_mirror.private_cloud_gateway_traffic}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.physical_mirror.private_cloud_gateway_traffic`

Upgrade from old version: `static_config.cloud-gateway-traffic`

**默认值**:
```yaml
inputs:
  cbpf:
    physical_mirror:
      private_cloud_gateway_traffic: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当 `inputs.cbpf.common.capture_mode` 为 `物理网络镜像` 模式，该参数配置为 `true` 时，deepflow-agent 会将流量识别为 NFVGW 流量。

## eBPF {#inputs.ebpf}

### Disabled {#inputs.ebpf.disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.disabled`

Upgrade from old version: `static_config.ebpf.disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

eBPF 特性的总开关。

### Socket {#inputs.ebpf.socket}

#### Uprobe {#inputs.ebpf.socket.uprobe}

##### Golang {#inputs.ebpf.socket.uprobe.golang}

###### Enabled {#inputs.ebpf.socket.uprobe.golang.enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.golang.enabled`

Upgrade from old version: `static_config.ebpf.uprobe-golang-trace-enabled, static_config.ebpf.uprobe-process-name-regexs.golang`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        golang:
          enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

Golang 程序 HTTP2/HTTPS 协议数据采集及零侵扰追踪特性的开启开关。

注意：开启此功能时，需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `ebpf.socket.uprobe.golang`。

###### 追踪超时时间 {#inputs.ebpf.socket.uprobe.golang.tracing_timeout}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.golang.tracing_timeout`

Upgrade from old version: `static_config.ebpf.go-tracing-timeout`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        golang:
          tracing_timeout: 120s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1d'] |

**详细描述**:

Golang 程序追踪时请求与响应之间的最大时间间隔，设置为 '0ns' 时，Golang 程序的零侵扰追踪特性自动关闭。

##### TLS {#inputs.ebpf.socket.uprobe.tls}

###### Enabled {#inputs.ebpf.socket.uprobe.tls.enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.tls.enabled`

Upgrade from old version: `static_config.ebpf.uprobe-openssl-trace-enabled, static_config.ebpf.uprobe-process-name-regexs.openssl`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        tls:
          enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

是否启用使用 openssl 库的进程以支持 HTTPS 协议数据采集。

可通过以下方式判断应用进程是否能够使用 `Uprobe hook openssl 库`来采集加密数据：
- 执行命令`sudo cat /proc/<PID>/maps | grep "libssl.so"`，若包含 openssl 相关信息
  则说明该进程正在使用 openssl 库。
- 如果上面没有搜到 "libssl.so" 也可能是静态编译了，这时候我们可以通过下面方式确认：
  执行命令 `sudo nm /proc/<PID>/exe | grep SSL_write` 若包含 `SSL_write` 相关信息如：`0000000000502ac0 T SSL_write`
  则说明该进程正在使用静态编译的 openssl 库。

启用后，deepflow-agent 将获取符合正则表达式匹配的进程信息，并 Hook openssl 库的相应加解密接口。
在日志中您会看到类似如下信息：
```
[eBPF] INFO openssl uprobe, pid:1005, path:/proc/1005/root/usr/lib64/libssl.so.1.0.2k
或者
[eBPF] INFO openssl uprobe, pid:28890, path:/proc/28890/root/usr/sbin/nginx
```

注意：开启此功能后，Envoy mTLS 流量可自动完成追踪；
若为非 Envoy 流量，则需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `ebpf.socket.uprobe.tls`。

##### DPDK {#inputs.ebpf.socket.uprobe.dpdk}

###### DPDK 应用命令名称 {#inputs.ebpf.socket.uprobe.dpdk.command}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.dpdk.command`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        dpdk:
          command: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

设置 DPDK 应用的命令名称, eBPF 会自动寻找并进行追踪采集数据包

配置样例: 如果命令行是 `/usr/bin/mydpdk`, 可以配置成 `command: mydpdk`, 并设置 `inputs.cbpf.special_network.dpdk.source = eBPF`

在 DPDK 作为 vhost-user 后端的场景中，虚拟机与 DPDK 应用之间通过 virtqueue（vring）进行数据交换。
eBPF 可以在无需修改 DPDK 或虚拟机的前提下，自动 hook 到 vring 接口，实现对传输数据包的捕获和分析，
无需额外配置即可实现流量可观测。相比之下，若要捕获物理网卡上的数据包，则需要配合 DPDK 的驱动接口进行显式配置。

###### DPDK 应用数据包接收 hook 点设置 {#inputs.ebpf.socket.uprobe.dpdk.rx_hooks}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.dpdk.rx_hooks`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        dpdk:
          rx_hooks: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

根据实际的网卡驱动填写合适的数据包接收 hook 点，可以利用命令 'lspci -vmmk' 寻找网卡驱动类型例如：
```
Slot:   04:00.0
Class:  Ethernet controller
Vendor: Intel Corporation
Device: Ethernet Controller XL710 for 40GbE QSFP+
SVendor:        Unknown vendor 1e18
SDevice:        Device 4712
Rev:    02
Driver: igb_uio
Module: i40e
```
上面的 "Driver: igb_uio" 说明是 DPDP 纳管的设备 (除此之外还有 "vfio-pci", "uio_pci_generic"
也被 DPDK 纳管), 真实驱动是 'i40e' (从 'Module: i40e' 得到)

可以使用 deepflow 提供的可持续剖析功能对 DPDK 应用做函数剖析查看具体接口名字，也可以使用 perf 命令
在agent所在节点上运行 `perf record -F97 -a -g -p <dpdk应用进程号> -- sleep 30`，
`perf script | grep -E 'recv|xmit|rx|tx' | grep <drive_name>` (`drive_name` may be `ixgbe/i40e/mlx5`)
来确认驱动接口。

下面列出了不同驱动对应的接口名称，仅供参考:
 1. Physical NIC Drivers:
     - Intel Drivers:
       - ixgbe:   Supports Intel 82598/82599/X520/X540/X550 series NICs.
         - rx: ixgbe_recv_pkts, ixgbe_recv_pkts_vec
         - tx: ixgbe_xmit_pkts, ixgbe_xmit_fixed_burst_vec, ixgbe_xmit_pkts_vec
       - i40e:    Supports Intel X710, XL710 series NICs.
         - rx: i40e_recv_pkts
         - tx: i40e_xmit_pkts
       - ice:     Supports Intel E810 series NICs.
         - rx: ice_recv_pkts
         - tx: ice_xmit_pkts
     - Mellanox Drivers:
       - mlx4:    Supports Mellanox ConnectX-3 series NICs.
         - rx: mlx4_rx_burst
         - tx: mlx4_tx_burst
       - mlx5:    Supports Mellanox ConnectX-4, ConnectX-5, ConnectX-6 series NICs.
         - rx: mlx5_rx_burst, mlx5_rx_burst_vec, mlx5_rx_burst_mprq
         - tx: Pending confirmation
     - Broadcom Drivers:
       - bnxt:    Supports Broadcom NetXtreme series NICs.
         - rx: bnxt_recv_pkts, bnxt_recv_pkts_vec (x86, Vector mode receive)
         - tx: bnxt_xmit_pkts, bnxt_xmit_pkts_vec (x86, Vector mode transmit)
  2. Virtual NIC Drivers:
     - Virtio Driver:
       - virtio:  Supports Virtio-based virtual network interfaces.
         - rx: virtio_recv_pkts, virtio_recv_mergeable_pkts_packed, virtio_recv_pkts_packed,
               virtio_recv_pkts_vec, virtio_recv_pkts_inorder, virtio_recv_mergeable_pkts
         - tx: virtio_xmit_pkts_packed, virtio_xmit_pkts,
     - VMXNET3 Driver:
       - vmxnet3: Supports VMware's VMXNET3 virtual NICs.
         - rx: vmxnet3_recv_pkts
         - tx: vmxnet3_xmit_pkts

配置样例: `rx_hooks: [ixgbe_recv_pkts, i40e_recv_pkts, virtio_recv_pkts, virtio_recv_mergeable_pkts]`

注意：在当前 DPDK 驱动接口的突发模式下发送和接收数据包时，旧版 Linux 内核（低于 5.2）的 eBPF 指令数量限制为 4096。
因此，在 DPDK 捕获数据包期间，最多只能捕获 16 个数据包。对于 Linux 5.2 及以上版本的内核，最多可捕获 32 个数
据包（这通常是 DPDK 突发模式的默认值）。对于低于 Linux 5.2 的内核，如果突发大小超过 16，可能会发生数据包丢失。

###### DPDK 应用数据包发送 hook 点设置 {#inputs.ebpf.socket.uprobe.dpdk.tx_hooks}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.dpdk.tx_hooks`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        dpdk:
          tx_hooks: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

根据实际的网卡驱动填写合适的数据包发送 hook 点, 获取驱动方法和发送hook点设置以及注意事项参考 `inputs.ebpf.socket.uprobe.dpdk.rx_hooks` 的说明.

配置样例: `tx_hooks: [i40e_xmit_pkts, virtio_xmit_pkts_packed, virtio_xmit_pkts]`

#### Kprobe {#inputs.ebpf.socket.kprobe}

##### 禁用 kprobe {#inputs.ebpf.socket.kprobe.disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当设置为 true 时，kprobe 功能将被禁用。

##### 启用 Unix Socket 追踪 {#inputs.ebpf.socket.kprobe.enable_unix_socket}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.enable_unix_socket`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        enable_unix_socket: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当设置为 true 时，启用 Unix Socket 追踪。

##### 黑名单 {#inputs.ebpf.socket.kprobe.blacklist}

###### 端口号 {#inputs.ebpf.socket.kprobe.blacklist.ports}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.blacklist.ports`

Upgrade from old version: `static_config.ebpf.kprobe-blacklist.port-list`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        blacklist:
          ports: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

TCP 和 UDP 的端口黑名单列表。端口号列入黑名单的 socket 将被 Kprobe 采集忽略。黑名单
生效优先级高于 kprobe 白名单。

配置样例: `ports: 80,1000-2000`

##### 白名单 {#inputs.ebpf.socket.kprobe.whitelist}

###### 白名单 {#inputs.ebpf.socket.kprobe.whitelist.ports}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.whitelist.ports`

Upgrade from old version: `static_config.ebpf.kprobe-whitelist.port-list`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        whitelist:
          ports: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

TCP 和 UDP 的端口白名单列表，白名单生效优先级低于 kprobe 黑名单。
未列入黑名单、白名单的端口用 kprobe 做采集。

配置样例: `ports: 80,1000-2000`

#### 调优 {#inputs.ebpf.socket.tunning}

##### 最大采集速率 {#inputs.ebpf.socket.tunning.max_capture_rate}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.socket.tunning.max_capture_rate`

Upgrade from old version: `static_config.ebpf.global-ebpf-pps-threshold`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        max_capture_rate: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Per Second |
| Range | [0, 64000000] |

**详细描述**:

eBPF 数据的最大采集速率，设置为 `0` 表示不对 deepflow-agent 的 eBPF 数据采集速率做限制。

##### 禁用 syscall_trace_id 相关的计算 {#inputs.ebpf.socket.tunning.syscall_trace_id_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.tunning.syscall_trace_id_disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        syscall_trace_id_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当 trace_id 注入所有请求时，所有请求的 syscall_trace_id 计算逻辑可以关闭。这将大大减少
eBPF hook 进程的 CPU 消耗。

##### 禁用预分配内存 {#inputs.ebpf.socket.tunning.map_prealloc_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.tunning.map_prealloc_disabled`

Upgrade from old version: `static_config.ebpf.map-prealloc-disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        map_prealloc_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当完整的map预分配过于昂贵时，将此配置设置为 `true` 可以防止在定义map时进行内存预分配，
但这可能会导致一些性能下降。此配置仅适用于 `BPF_MAP_TYPE_HASH` 类型的 bpf map。
目前适用于 socket trace 和 uprobe Golang/OpenSSL trace 功能。禁用内存预分配大约会减少45M的内存占用。

##### 启用fentry/fexit特性 {#inputs.ebpf.socket.tunning.fentry_enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.tunning.fentry_enabled`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        fentry_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

使用 fentry/fexit 特性说明
- 相比传统的 kprobes，fentry 和 fexit 程序提供了更高的性能和可用性，可带来约 5%–10% 的性能提升。
- 部分 Linux 内核对该特性支持不够完善，可能导致内核 BUG 和节点崩溃。已知的 BUG 修复包括：
  - TencentOS Linux kernel 5.4.119 的修复
    [https://github.com/torvalds/linux/commit/c3d6324f841bab2403be6419986e2b1d1068d423](https://github.com/torvalds/linux/commit/c3d6324f841bab2403be6419986e2b1d1068d423)
  - Alibaba Cloud Linux kernel 5.10.23 的修复
    [https://github.com/gregkh/linux/commit/e21d2b92354b3cd25dd774ebb0f0e52ff04a7861](https://github.com/gregkh/linux/commit/e21d2b92354b3cd25dd774ebb0f0e52ff04a7861)
- 内核建议：若要启用 fentry/fexit 特性，推荐使用 Linux kernel 5.10.28 及以上版本，以确保稳定性和性能。

#### 预处理 {#inputs.ebpf.socket.preprocess}

##### 乱序重排（OOOR）缓冲区大小 {#inputs.ebpf.socket.preprocess.out_of_order_reassembly_cache_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.preprocess.out_of_order_reassembly_cache_size`

Upgrade from old version: `static_config.ebpf.syscall-out-of-order-cache-size`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      preprocess:
        out_of_order_reassembly_cache_size: 16
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8, 1024] |

**详细描述**:

由于 eBPF socket 事件是以批处理的方式向用户态空间发送数据，同一个应用调用的请求、响应由不同 CPU 处理时，可能
会出现请求、响应乱序的情况，开启 Syscall 数据乱序重排特性后，每个 TCP/UDP 流会缓存一定数量的 eBPF socket
事件，以修正乱序数据对应用调用解析的影响。该参数设置了每个 TCP/UDP 流可以缓存的 eBPF socket 事件数量上限（每
条事件数据占用的字节数上限受 `processors.request_log.tunning.payload_truncation` 控制）。在 Syscall 数据乱序较严重
导致应用调用采集不全的环境中，可适当调大该参数。

##### 乱序重排（OOOR）协议列表 {#inputs.ebpf.socket.preprocess.out_of_order_reassembly_protocols}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.preprocess.out_of_order_reassembly_protocols`

Upgrade from old version: `static_config.ebpf.syscall-out-of-order-reassembly`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      preprocess:
        out_of_order_reassembly_protocols: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置后 deepflow-agent 将对指定应用协议的处理增加乱序重排过程。注意：（1）开启特性将消耗更多的内存，因此
需关注 agent 内存用量；（2）配置`HTTP2`或`gRPC`会全部开启这两个协议

##### 分段重组（SR）协议列表 {#inputs.ebpf.socket.preprocess.segmentation_reassembly_protocols}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.preprocess.segmentation_reassembly_protocols`

Upgrade from old version: `static_config.ebpf.syscall-segmentation-reassembly`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      preprocess:
        segmentation_reassembly_protocols: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置后 deepflow-agent 将对指定应用协议的处理增加分片重组过程，将多个 Syscall 的内容分片重组后再进行
协议解析，以增强应用协议的采集成功率。

注意：
1. 该特性的生效的前提条件是`out_of_order_reassembly_protocols`开启并生效；
   - 支持协议：[https://www.deepflow.io/docs/zh/features/l7-protocols/overview/](https://www.deepflow.io/docs/zh/features/l7-protocols/overview/)
2. 配置`HTTP2`或`gRPC`会全部开启这两个协议

### TCP Option Trace {#inputs.ebpf.socket.sock_ops.tcp_option_trace}

#### 启用 {#inputs.ebpf.socket.sock_ops.tcp_option_trace.enabled}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.socket.sock_ops.tcp_option_trace.enabled`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      sock_ops:
        tcp_option_trace:
          enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

是否开启 TCP Option Tracing SockOps 程序，用于在满足条件的 TCP 连接上注入 DeepFlow 元数据（如进程 PID）。

注意：该功能依赖 cgroup v2（统一层级）。在 cgroup v1 主机上 SockOps 绑定会失败。

限制：PID 跟踪依赖 `agent/src/ebpf/user/extended/bpf/tcp_option_tracing.bpf.c` 中的 per-CPU syscall map。当 CPU 拥堵或软中断在不同 CPU 上处理 TCP 时，注入的元数据可能缺失或过期。

#### PID 注入窗口 {#inputs.ebpf.socket.sock_ops.tcp_option_trace.sampling_window_bytes}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.socket.sock_ops.tcp_option_trace.sampling_window_bytes`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      sock_ops:
        tcp_option_trace:
          sampling_window_bytes: 16384
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Bytes |
| Range | [0, 1048576] |

**详细描述**:

控制两次 PID 注入之间的最小 TCP 负载间隔字节数。缺省为 16KB，与历史行为一致；值越小注入越频繁，值越大越稀疏。设置为 `0` 表示关闭采样，对每个满足条件的数据包都注入 PID。

### File {#inputs.ebpf.file}

#### IO 事件 {#inputs.ebpf.file.io_event}

##### 采集模式 {#inputs.ebpf.file.io_event.collect_mode}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.file.io_event.collect_mode`

Upgrade from old version: `static_config.ebpf.io-event-collect-mode`

**默认值**:
```yaml
inputs:
  ebpf:
    file:
      io_event:
        collect_mode: 1
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | 禁用 |
| 1 | 调用生命周期 |
| 2 | 全部 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

采集模式：
- 禁用：不采集任何文件 IO 事件。
- 调用生命周期：仅采集调用生命周期内的文件 IO 事件。
- 全部：采集所有的文件 IO 事件。

说明：
- 为了获取文件的完整路径，需要结合进程的挂载信息进行路径拼接。然而，一些进程在完成任务后会迅速退出，
  此时我们处理其产生的文件读写数据时，可能已无法从 /proc/[pid]/mountinfo 中获取挂载信息，导致路径不
  完整（缺少挂载点）。我们对于 50ms 以下生存期的进程，文件路径会缺少挂载点信息。对于长期运行的进程，
  则不存在该问题。

##### 最小耗时 {#inputs.ebpf.file.io_event.minimal_duration}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.file.io_event.minimal_duration`

Upgrade from old version: `static_config.ebpf.io-event-minimal-duration`

**默认值**:
```yaml
inputs:
  ebpf:
    file:
      io_event:
        minimal_duration: 1ms
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1ns', '1s'] |

**详细描述**:

deepflow-agent 所采集的文件 IO 事件的时延下限阈值，操作系统中时延低于此阈值
的文件 IO 事件将被忽略。

##### 启用虚拟文件采集 {#inputs.ebpf.file.io_event.enable_virtual_file_collect}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.file.io_event.enable_virtual_file_collect`

**默认值**:
```yaml
inputs:
  ebpf:
    file:
      io_event:
        enable_virtual_file_collect: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当设置为 true 时，deepflow-agent 将采集发生在虚拟文件系统上的文件
I/O 事件（例如 /proc、/sys、/run 等由内核动态生成的伪文件系统）。
当设置为 false 时，将不会采集虚拟文件系统上的文件 I/O 事件。

### Profile {#inputs.ebpf.profile}

#### 栈回溯 {#inputs.ebpf.profile.unwinding}

##### 禁用 DWARF 栈回溯 {#inputs.ebpf.profile.unwinding.dwarf_disabled}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_disabled`

Upgrade from old version: `static_config.ebpf.dwarf-disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_disabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

默认设置为 `true`，将禁用 DWARF 栈回溯，对所有进程使用基于帧指针的回溯，如果进程不包含帧指针将无法显示正常的栈。
设置为 `false` 将对所有不包含帧指针的进程启用 DWARF 回溯。采集器使用启发式算法判断待剖析进程是否包含帧指针。
设置 `dwarf_regex` 后，将强制对匹配的进程使用 DWARF 回溯。

##### DWARF 回溯进程匹配正则表达式 {#inputs.ebpf.profile.unwinding.dwarf_regex}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_regex`

Upgrade from old version: `static_config.ebpf.dwarf-regex`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_regex: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

如设置为空，采集器将使用启发式算法判断待剖析进程是否包含帧指针，并对不包含帧指针的进程使用 DWARF 栈回溯。
如设置为合法正则表达式，采集器将不再自行推断进程是否包含帧指针，改用该正则表达式对进程名进行匹配，仅对匹配的进程使用 DWARF 帧回溯。

##### DWARF 回溯进程表容量 {#inputs.ebpf.profile.unwinding.dwarf_process_map_size}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_process_map_size`

Upgrade from old version: `static_config.ebpf.dwarf-process-map-size`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_process_map_size: 1024
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 131072] |

**详细描述**:

每个需要进行 DWARF 回溯的进程在该表中有一条记录，用于关联进程和回溯记录分片。
每条记录大约占 8K 内存，默认配置大约需要分配 8M 内核内存。
由于是哈希表，配置可以比最大进程号低。
该配置只在 DWARF 功能开启时生效。

##### DWARF 回溯分片表容量 {#inputs.ebpf.profile.unwinding.dwarf_shard_map_size}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_shard_map_size`

Upgrade from old version: `static_config.ebpf.dwarf-shard-map-size`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_shard_map_size: 128
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 4096] |

**详细描述**:

DWARF 回溯记录分片数量。
每条记录大约占 1M 内存，默认配置大约需要分配 128M 内核内存。
该配置只在 DWARF 功能开启时生效。

#### On-CPU {#inputs.ebpf.profile.on_cpu}

##### Disabled {#inputs.ebpf.profile.on_cpu.disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.on_cpu.disabled`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      on_cpu:
        disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

eBPF On-CPU profile 数据的采集开关。

注意：开启此功能时，需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `ebpf.profile.on_cpu`。

##### 采样频率 {#inputs.ebpf.profile.on_cpu.sampling_frequency}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.on_cpu.sampling_frequency`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.frequency`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      on_cpu:
        sampling_frequency: 99
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 1000] |

**详细描述**:

eBPF On-CPU profile 数据的采样周期。

##### 按 CPU 聚合 {#inputs.ebpf.profile.on_cpu.aggregate_by_cpu}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.on_cpu.aggregate_by_cpu`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.cpu`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      on_cpu:
        aggregate_by_cpu: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

采集 On-CPU 采样数据时，是否获取 CPUID 的开关。
- `true`: 表示在采集 On-CPU 采样数据时获取 CPUID （On-CPU 剖析时，支持对单个 CPU 的分析）。
- `false`: 表示在采集 On-CPU 采样数据时不获取 CPUID （On-CPU 剖析时，不支持单个 CPU 的分析）。

#### Off-CPU {#inputs.ebpf.profile.off_cpu}

##### Disabled {#inputs.ebpf.profile.off_cpu.disabled}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.off_cpu.disabled`

Upgrade from old version: `static_config.ebpf.off-cpu-profile.disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      off_cpu:
        disabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

eBPF Off-CPU profile 数据的采集开关。

注意：开启此功能时，需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `ebpf.profile.off_cpu`。

##### 按 CPU 聚合 {#inputs.ebpf.profile.off_cpu.aggregate_by_cpu}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.off_cpu.aggregate_by_cpu`

Upgrade from old version: `static_config.ebpf.off-cpu-profile.cpu`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      off_cpu:
        aggregate_by_cpu: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

采集 Off-CPU 数据时，是否获取 CPUID 的开关。
- `true`: 表示在采集 Off-CPU 数据时获取 CPUID （Off-CPU 剖析时，支持对单个 CPU 的分析）。
- `false`: 表示在采集 Off-CPU 数据时不获取 CPUID （Off-CPU 剖析时，不支持单个 CPU 的分析）。

##### 最小阻塞时间 {#inputs.ebpf.profile.off_cpu.min_blocking_time}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.off_cpu.min_blocking_time`

Upgrade from old version: `static_config.ebpf.off-cpu-profile.minblock`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      off_cpu:
        min_blocking_time: 50us
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1h'] |

**详细描述**:

低于'最小阻塞时间'的 Off-CPU 数据将被 deepflow-agent 忽略，'最小阻塞时间'设置为 '0ns' 表示
采集所有的 Off-CPU 数据。由于 CPU 调度事件数量庞大（每秒可能超过一百万次），调小该参数将带来
明显的资源开销，如果需要跟踪大时延的调度阻塞事件，建议调大该参数，以降低资源开销。另外，deepflow-agent
不采集阻塞超过 1 小时的事件。

#### Memory {#inputs.ebpf.profile.memory}

##### Disabled {#inputs.ebpf.profile.memory.disabled}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.disabled`

Upgrade from old version: `static_config.ebpf.memory-profile.disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        disabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

eBPF memory profile 数据的采集开关。

注意：开启此功能时，需要同时在 `inputs.proc.process_matcher` 中进一步指定具体的进程列表，
即 `inputs.proc.process_matcher.[*].enabled_features` 中需要包含 `ebpf.profile.memory`。

##### 内存剖析上报间隔 {#inputs.ebpf.profile.memory.report_interval}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.report_interval`

Upgrade from old version: `static_config.ebpf.memory-profile.report-interval`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        report_interval: 10s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '60s'] |

**详细描述**:

deepflow-agent 聚合和上报内存剖析数据的间隔。

##### 进程分配地址 LRU 长度 {#inputs.ebpf.profile.memory.allocated_addresses_lru_len}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.allocated_addresses_lru_len`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        allocated_addresses_lru_len: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 4194704] |

**详细描述**:

采集器使用 LRU 缓存记录进程分配的地址，以避免内存使用失控。每个 LRU 条目大约占 32B 内存。

##### 排序长度 {#inputs.ebpf.profile.memory.sort_length}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.sort_length`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        sort_length: 16384
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 65536] |

**详细描述**:

为了匹配 mallocs 和 frees，内存剖析会在处理前对数据按时间戳排序。
该参数是排序数组的长度。
配置该选项时先按说明调整 `sort_interval` 参数，在参考采集器性能统计 `deepflow_agent_ebpf_memory_profiler` 中
`dequeued_by_length` 和 `dequeued_by_interval` 指标，在保证前者小于后者几倍的前提下适当调小该参数。

##### 排序间隔 {#inputs.ebpf.profile.memory.sort_interval}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.sort_interval`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        sort_interval: 1500ms
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1ns', '10s'] |

**详细描述**:

为了匹配 mallocs 和 frees，内存剖析会在处理前对数据按时间戳排序。
该参数控制排序数组中第一个和最后一个元素之间的时间间隔的最大值。
配置该选项可以参考采集器性能统计 `deepflow_agent_ebpf_memory_profiler` 中
`time_backtracked` 指标，增大该参数使之为 0 即可。注意可能需要相应增大 `sort_length` 参数。

##### 队列大小 {#inputs.ebpf.profile.memory.queue_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.queue_size`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        queue_size: 32768
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [4096, 64000000] |

**详细描述**:

内存剖析组件内部的队列大小。
配置该选项可以参考采集器性能统计 `deepflow_agent_ebpf_memory_profiler` 中
`overwritten` 和 `pending` 指标，增大该配置使得前者为 0，后者不高于该配置即可。

#### 预处理 {#inputs.ebpf.profile.preprocess}

##### 函数栈压缩 {#inputs.ebpf.profile.preprocess.stack_compression}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.preprocess.stack_compression`

Upgrade from old version: `static_config.ebpf.preprocess.stack-compression`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      preprocess:
        stack_compression: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

发送数据之前压缩函数调用栈。压缩能够有效降低 agent 的内存开销、数据传输的带宽消耗、以及
ingester 的 CPU 开销，但是 Agent 也会因此消耗更多的 CPU。测试表明，将deepflow-agent 自身的
on-cpu 函数调用栈压缩，可以将带宽消耗降低 `x` 倍，但会使得 agent 额外消耗 `y%` 的 CPU。

#### 语言特定剖析 {#inputs.ebpf.profile.languages}

控制对哪些解释型语言进行剖析。禁用不使用的语言可以节省每个语言约 5-6 MB 内存。
总内存占用：~17-20 MB（全部启用），~6.1 MB（仅 Python），~5.2 MB（仅 PHP），~6.4 MB（仅 Node.js）。

##### 禁用 Python 剖析 {#inputs.ebpf.profile.languages.python_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.languages.python_disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      languages:
        python_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

禁用 Python 解释器剖析。禁用后将不采集 Python 进程的函数调用栈，
可节省约 6.1 MB 内核内存（python_tstate_addr_map、python_unwind_info_map、python_offsets_map）。

##### 禁用 PHP 剖析 {#inputs.ebpf.profile.languages.php_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.languages.php_disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      languages:
        php_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

禁用 PHP 解释器剖析。禁用后将不采集 PHP 进程的函数调用栈，
可节省约 5.2 MB 内核内存（php_unwind_info_map、php_offsets_map）。

##### 禁用 Node.js 剖析 {#inputs.ebpf.profile.languages.nodejs_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.languages.nodejs_disabled`

**默认值**:
```yaml
inputs:
  ebpf:
    profile:
      languages:
        nodejs_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

禁用 Node.js（V8）解释器剖析。禁用后将不采集 Node.js 进程的函数调用栈，
可节省约 6.4 MB 内核内存（v8_unwind_info_map）。

### 调优 {#inputs.ebpf.tunning}

#### 采集队列大小 {#inputs.ebpf.tunning.collector_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.collector_queue_size`

Upgrade from old version: `static_config.ebpf-collector-queue-size`

**默认值**:
```yaml
inputs:
  ebpf:
    tunning:
      collector_queue_size: 65535
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [4096, 64000000] |

**详细描述**:

以下 deepflow-agent 的 eBPF 数据采集队列大小（分别限制）：
- 0-ebpf-to-ebpf-collector
- 1-proc-event-to-sender
- 1-profile-to-sender

#### 用户态工作线程数 {#inputs.ebpf.tunning.userspace_worker_threads}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.userspace_worker_threads`

Upgrade from old version: `static_config.ebpf.thread-num`

**默认值**:
```yaml
inputs:
  ebpf:
    tunning:
      userspace_worker_threads: 1
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 1024] |

**详细描述**:

参与用户态数据处理的工作线程数量。实际最大值为主机 CPU 逻辑核心数。

#### Perf Page 数量 {#inputs.ebpf.tunning.perf_pages_count}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.perf_pages_count`

Upgrade from old version: `static_config.ebpf.perf-pages-count`

**默认值**:
```yaml
inputs:
  ebpf:
    tunning:
      perf_pages_count: 128
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [32, 8192] |

**详细描述**:

内核共享内存占用的页数。值为 `2^n (5 <= n <= 13)`。用于 perf 数据传输。
如果值在 `2^n` 和 `2^(n+1)` 之间，将自动调整到最小值 `2^n`。
页的大小为4KB。

#### 内核环形队列大小 {#inputs.ebpf.tunning.kernel_ring_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.kernel_ring_size`

Upgrade from old version: `static_config.ebpf.ring-size`

**默认值**:
```yaml
inputs:
  ebpf:
    tunning:
      kernel_ring_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8192, 131072] |

**详细描述**:

内核环形队列的大小。值为 `2^n (13 <= n <= 17)`。
如果值在 `2^n` 和 `2^(n+1)` 之间，将自动调整到最小值 `2^n`。

#### 最大 Socket 条目数 {#inputs.ebpf.tunning.max_socket_entries}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.max_socket_entries`

Upgrade from old version: `static_config.ebpf.max-socket-entries`

**默认值**:
```yaml
inputs:
  ebpf:
    tunning:
      max_socket_entries: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [10000, 2000000] |

**详细描述**:

设置 socket tracking 哈希表的最大条目数，根据实际场景中的并发请求数量而定。

#### Socket Map 回收阈值 {#inputs.ebpf.tunning.socket_map_reclaim_threshold}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.socket_map_reclaim_threshold`

Upgrade from old version: `static_config.ebpf.socket-map-max-reclaim`

**默认值**:
```yaml
inputs:
  ebpf:
    tunning:
      socket_map_reclaim_threshold: 120000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8000, 2000000] |

**详细描述**:

Socket map 表条目清理阈值。

#### 最大 Trace 条目数 {#inputs.ebpf.tunning.max_trace_entries}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.max_trace_entries`

Upgrade from old version: `static_config.ebpf.max-trace-entries`

**默认值**:
```yaml
inputs:
  ebpf:
    tunning:
      max_trace_entries: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [10000, 2000000] |

**详细描述**:

线程和协程追踪的最大哈希表条目数。

## 资源 {#inputs.resources}

### 推送间隔 {#inputs.resources.push_interval}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.push_interval`

Upgrade from old version: `platform_sync_interval`

**默认值**:
```yaml
inputs:
  resources:
    push_interval: 10s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '3600s'] |

**详细描述**:

deepflow-agent 主动向 deepflow-server 上报/同步资源信息的时间间隔。

### 启用云主机资源同步 {#inputs.resources.workload_resource_sync_enabled}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.workload_resource_sync_enabled`

**默认值**:
```yaml
inputs:
  resources:
    workload_resource_sync_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启开关后，deepflow-server 基于 deepflow-agent 上报的运行环境信息，生成一个云主机资源。
用于无法通过云平台 API 同步云主机资源的场景，也可用于同步非云环境中普通物理服务器的资源信息。

### 采集专有云资源 {#inputs.resources.private_cloud}

#### 启用云宿主机资源 {#inputs.resources.private_cloud.hypervisor_resource_enabled}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.private_cloud.hypervisor_resource_enabled`

Upgrade from old version: `platform_enabled`

**默认值**:
```yaml
inputs:
  resources:
    private_cloud:
      hypervisor_resource_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启开关后，deepflow-agent 将采集 KVM 或 Linux 宿主机中的 VM 信息和网络信息，并上报/同步至 deepflow-server。
采集的信息包括：
- raw_all_vm_xml
- raw_vm_states
- raw_ovs_interfaces
- raw_ovs_ports
- raw_brctl_show
- raw_vlan_config

#### 虚拟机 MAC 源 {#inputs.resources.private_cloud.vm_mac_source}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.private_cloud.vm_mac_source`

Upgrade from old version: `if_mac_source`

**默认值**:
```yaml
inputs:
  resources:
    private_cloud:
      vm_mac_source: 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | 网卡 MAC 地址 |
| 1 | 网卡名称 |
| 2 | Qemu XML 文件 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

配置 deepflow-agent 提取 VM 真实 MAC 地址的方法:
- 网卡 MAC 地址: 从 tap 接口的 MAC 地址中提取 VM 的 MAC 地址
- 网卡名称: 从 tap 接口的名字中提取 MAC 地址
- Qemu XML 文件: 从 VM XML 文件中提取 MAC 地址

#### 虚拟机 XML 文件夹 {#inputs.resources.private_cloud.vm_xml_directory}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.private_cloud.vm_xml_directory`

Upgrade from old version: `vm_xml_path`

**默认值**:
```yaml
inputs:
  resources:
    private_cloud:
      vm_xml_directory: /etc/libvirt/qemu/
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 100] |

**详细描述**:

宿主机中存放 VM XML 文件的目录

#### 虚拟机 MAC 映射脚本 {#inputs.resources.private_cloud.vm_mac_mapping_script}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.private_cloud.vm_mac_mapping_script`

Upgrade from old version: `static_config.tap-mac-script`

**默认值**:
```yaml
inputs:
  resources:
    private_cloud:
      vm_mac_mapping_script: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 100] |

**详细描述**:

复杂环境中，TAP 网卡的 MAC 地址映射关系可以通过编写脚本实现。使用脚本时需要满足以下条件：
1. if_mac_source = 2
2. tap_mode = 0
3. TAP 网卡的名称与虚拟机 XML 文件中的名称相同
4. 脚本输出格式如下：
   - tap2d283dfe,11:22:33:44:55:66
   - tap2d283223,aa:bb:cc:dd:ee:ff

### 采集 K8s 资源 {#inputs.resources.kubernetes}

#### K8s 命名空间 {#inputs.resources.kubernetes.kubernetes_namespace}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.kubernetes_namespace`

Upgrade from old version: `static_config.kubernetes-namespace`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      kubernetes_namespace: null
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

指定采集器获取 K8s 资源时的命名空间

#### K8s API 资源 {#inputs.resources.kubernetes.api_resources}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources`

Upgrade from old version: `static_config.kubernetes-resources`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - name: namespaces
      - name: nodes
      - name: pods
      - name: replicationcontrollers
      - name: services
      - name: daemonsets
      - name: deployments
      - name: replicasets
      - name: statefulsets
      - name: ingresses
      - name: configmaps
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

指定采集器采集的 K8s 资源。

列表中的条目格式如下：
{
    name: string
    group: string
    version: string
    disabled: bool
    field_selector: string
}

默认采集的资源如下：
- namespaces
- nodes
- pods
- replicationcontrollers
- services
- daemonsets
- deployments
- replicasets
- statefulsets
- ingresses
- configmaps

禁用某个资源，在列表中添加 `disabled: true` 的条目：
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - name: services
        disabled: true
```

启用某个资源，在列表中添加该资源的条目。注意该设置会覆盖默认的资源采集。
例如，要启用在 group `apps` 和 `apps.kruise.io` 中的 `statefulsets`，需要添加两个条目：
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - name: statefulsets
        group: apps
      - name: statefulsets
        group: apps.kruise.io
        version: v1beta1
```

要采集 openshift 中的 `routes`，可以使用以下设置：
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - name: ingresses
        disabled: true
      - name: routes
```

##### 名称 {#inputs.resources.kubernetes.api_resources.name}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.name`

Upgrade from old version: `static_config.kubernetes-resources.name`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - name: ''
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| namespaces | |
| nodes | |
| pods | |
| replicationcontrollers | |
| services | |
| daemonsets | |
| deployments | |
| replicasets | |
| statefulsets | |
| ingresses | |
| routes | |
| servicerules | |
| clonesets | |
| ippools | |
| opengaussclusters | |
| configmaps | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

K8s API 资源名

##### 组 {#inputs.resources.kubernetes.api_resources.group}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.group`

Upgrade from old version: `static_config.kubernetes-resources.group`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - group: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

K8s API 资源组

##### 版本 {#inputs.resources.kubernetes.api_resources.version}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.version`

Upgrade from old version: `static_config.kubernetes-resources.version`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - version: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

K8s API 版本

##### Disabled {#inputs.resources.kubernetes.api_resources.disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.disabled`

Upgrade from old version: `static_config.kubernetes-resources.disabled`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

禁用 K8s API 资源

##### Field Selector {#inputs.resources.kubernetes.api_resources.field_selector}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.field_selector`

Upgrade from old version: `static_config.kubernetes-resources.field-selector`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - field_selector: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

K8s API 资源字段选择器

#### K8s API List 页大小 {#inputs.resources.kubernetes.api_list_page_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_list_page_size`

Upgrade from old version: `static_config.kubernetes-api-list-limit`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_list_page_size: 1000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [10, 4294967295] |

**详细描述**:

用于指定 K8s 资源获取分页大小。

#### K8s API List 最大间隔 {#inputs.resources.kubernetes.api_list_max_interval}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_list_max_interval`

Upgrade from old version: `static_config.kubernetes-api-list-interval`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      api_list_max_interval: 10m
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10m', '30d'] |

**详细描述**:

当 watcher 未收到更新时，获取 K8s 资源的间隔时间。

#### Ingress Flavour {#inputs.resources.kubernetes.ingress_flavour}

**标签**:

<mark></mark>
<mark>deprecated</mark>

**FQCN**:

`inputs.resources.kubernetes.ingress_flavour`

Upgrade from old version: `static_config.ingress-flavour`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      ingress_flavour: kubernetes
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

#### Pod MAC 地址采集方法 {#inputs.resources.kubernetes.pod_mac_collection_method}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.pod_mac_collection_method`

Upgrade from old version: `static_config.kubernetes-poller-type`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      pod_mac_collection_method: adaptive
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| adaptive | |
| active | |
| passive | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

- passive: deepflow-agent 采集 ARP/ND 数据包 计算其他 POD 的 MAC 和 IP 信息。
- active: deepflow-agent 通过 setns 进入其他 POD 的 netns 查询 MAC 和 IP 信息（部署
  时需要 SYS_ADMIN 权限）。
- adaptive: deepflow-agent 优先使用 active 模式获取其他 POD 的 MAC 和 IP 信息。

### 从控制器拉取资源 {#inputs.resources.pull_resource_from_controller}

DeepFlow-server 从控制器拉取资源的配置。
DeepFlow-agent 不会读取此部分。

#### 云平台过滤器 {#inputs.resources.pull_resource_from_controller.domain_filter}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.pull_resource_from_controller.domain_filter`

Upgrade from old version: `domains`

**默认值**:
```yaml
inputs:
  resources:
    pull_resource_from_controller:
      domain_filter:
      - '0'
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

在运行过程中 deepflow-agent 周期性从 deepflow-server 获取 IP、MAC 列表，用于
向采集的观测数据注入标签。该参数可以控制向 deepflow-agent 发送的 IP、MAC 数据范围，
以减少下发的数据量。当业务系统中不存在跨云平台的服务访问时，可以配置仅向 deepflow-agent
下发本云平台的数据。参数的默认值为`0`，表示获取所有云平台的数据；也可以设置 lcuuid 列表，
仅获取部分云平台的数据。

#### 仅下发本集群中的 K8s Pod IP {#inputs.resources.pull_resource_from_controller.only_kubernetes_pod_ip_in_local_cluster}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.pull_resource_from_controller.only_kubernetes_pod_ip_in_local_cluster`

Upgrade from old version: `pod_cluster_internal_ip`

**默认值**:
```yaml
inputs:
  resources:
    pull_resource_from_controller:
      only_kubernetes_pod_ip_in_local_cluster: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

运行过程中 deepflow-agent 周期性从 deepflow-server 获取 IP、MAC 列表，用于
向采集的观测数据注入标签。该参数可以控制向 deepflow-agent 发送的 IP、MAC 数据范围，
减少下发的数据量。当 Kubernetes 内部的 POD IP 不会直接与外部通信时，可以配置仅向 deepflow-agent
下发本集群的 POD IP、MAC 数据。参数默认值为 `false`，表示发送全部。

## 集成 {#inputs.integration}

### Enabled {#inputs.integration.enabled}

**标签**:

`hot_update`

**FQCN**:

`inputs.integration.enabled`

Upgrade from old version: `external_agent_http_proxy_enabled`

**默认值**:
```yaml
inputs:
  integration:
    enabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开关开启后，deepflow-agent 将开启外部数据的接收服务接口，以集成来自 Prometheus、
Telegraf、OpenTelemetry 和 Skywalking 的数据。

### 监听端口 {#inputs.integration.listen_port}

**标签**:

`hot_update`

**FQCN**:

`inputs.integration.listen_port`

Upgrade from old version: `external_agent_http_proxy_port`

**默认值**:
```yaml
inputs:
  integration:
    listen_port: 38086
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

deepflow-agent 外部数据接收服务的监听端口。

### 压缩 {#inputs.integration.compression}

#### Trace {#inputs.integration.compression.trace}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.compression.trace`

Upgrade from old version: `static_config.external-agent-http-proxy-compressed`

**默认值**:
```yaml
inputs:
  integration:
    compression:
      trace: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后，deepflow-agent 将对集成的追踪数据进行压缩处理，压缩比例在 5:1~10:1 之间。注意：
开启此特性将增加 deepflow-agent 的 CPU 消耗。

#### Profile {#inputs.integration.compression.profile}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.compression.profile`

Upgrade from old version: `static_config.external-agent-http-proxy-profile-compressed`

**默认值**:
```yaml
inputs:
  integration:
    compression:
      profile: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后，deepflow-agent 将对集成的剖析数据进行压缩处理，压缩比例在 5:1~10:1 之间。注意：
开启此特性将增加 deepflow-agent 的 CPU 消耗。

### Prometheus 额外 Label {#inputs.integration.prometheus_extra_labels}

deepflow-agent 支持从 Prometheus RemoteWrite 的 http header 中获取额外的 label。

#### Enabled {#inputs.integration.prometheus_extra_labels.enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.enabled`

Upgrade from old version: `static_config.prometheus-extra-config.enabled`

**默认值**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

Prometheus 额外 lable 的获取开关。

#### 额外 Label {#inputs.integration.prometheus_extra_labels.extra_labels}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.extra_labels`

Upgrade from old version: `static_config.prometheus-extra-config.labels`

**默认值**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      extra_labels: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

Prometheus 额外 label 的列表。

#### Label 键总长度限制 {#inputs.integration.prometheus_extra_labels.label_length}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.label_length`

Upgrade from old version: `static_config.prometheus-extra-config.labels-limit`

**默认值**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      label_length: 1024
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [1024, 1048576] |

**详细描述**:

deepflow-agent 对 Prometheus 额外 label 解析并采集时，key 字段长度总和的上限。

#### Label 值总长度限制 {#inputs.integration.prometheus_extra_labels.value_length}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.value_length`

Upgrade from old version: `static_config.prometheus-extra-config.values-limit`

**默认值**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      value_length: 4096
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [4096, 4194304] |

**详细描述**:

deepflow-agent 对 Prometheus 额外 label 解析并采集时，value 字段长度总和的上限。

### 特性开关 {#inputs.integration.feature_control}

#### 禁用 Profile 集成 {#inputs.integration.feature_control.profile_integration_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.profile_integration_disabled`

Upgrade from old version: `static_config.external-profile-integration-disabled`

**默认值**:
```yaml
inputs:
  integration:
    feature_control:
      profile_integration_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

#### 禁用 Trace 集成 {#inputs.integration.feature_control.trace_integration_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.trace_integration_disabled`

Upgrade from old version: `static_config.external-trace-integration-disabled`

**默认值**:
```yaml
inputs:
  integration:
    feature_control:
      trace_integration_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

#### 禁用 Metric 集成 {#inputs.integration.feature_control.metric_integration_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.metric_integration_disabled`

Upgrade from old version: `static_config.external-metric-integration-disabled`

**默认值**:
```yaml
inputs:
  integration:
    feature_control:
      metric_integration_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

#### 禁用 Log 集成 {#inputs.integration.feature_control.log_integration_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.log_integration_disabled`

Upgrade from old version: `static_config.external-log-integration-disabled`

**默认值**:
```yaml
inputs:
  integration:
    feature_control:
      log_integration_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

## vector {#inputs.vector}

### 启用 Vector 组件 {#inputs.vector.enabled}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.vector.enabled`

**默认值**:
```yaml
inputs:
  vector:
    enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

对 Vector 组件的开关控制。

### Vector 组件配置控制 {#inputs.vector.config}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.vector.config`

**默认值**:
```yaml
inputs:
  vector:
    config: null
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

Vector 组件的具体配置，所有可用配置可在此链接中查找：[vector.dev](https://vector.dev/docs/reference/configuration)
以下提供一份抓取 kubernetes 日志、宿主机指标及 kubernetes kubelet 指标的示例，并将这些数据发送到 DeepFlow-Agent。

抓取主机指标
`K8S_NODE_NAME_FOR_DEEPFLOW` 变量仅容器环境必须，非容器环境可以去掉
```yaml
sources:
  host_metrics:
    type: host_metrics
    scrape_interval_secs: 10
    namespace: node
transforms:
  host_metrics_relabel:
    type: remap
    inputs:
    - host_metrics
    source: |
      .tags.instance = "${K8S_NODE_IP_FOR_DEEPFLOW}"
      host_name, _ = get_env_var("K8S_NODE_NAME_FOR_DEEPFLOW")
      if !is_empty(host_name) {
        .tags.host = host_name
      }
      metrics_map = {
        "boot_time": "boot_time_seconds",
        "memory_active_bytes": "memory_Active_bytes",
        "memory_available_bytes": "memory_MemAvailable_bytes",
        "memory_buffers_bytes": "memory_Buffers_bytes",
        "memory_cached_bytes": "memory_Cached_bytes",
        "memory_free_bytes": "memory_MemFree_bytes",
        "memory_swap_free_bytes": "memory_SwapFree_bytes",
        "memory_swap_total_bytes": "memory_SwapTotal_bytes",
        "memory_swap_used_bytes": "memory_SwapCached_bytes",
        "memory_total_bytes": "memory_MemTotal_bytes",
        "network_transmit_packets_drop_total": "network_transmit_drop_total",
        "uptime": "uname_info",
        "filesystem_total_bytes": "filesystem_size_bytes",
      }
      metric_name = get!(value: metrics_map, path: [.name])
      if !is_null(metric_name) {
        .name = metric_name
      }
      if .tags.collector == "filesystem" {
        .tags.fstype = .tags.filesystem
        del(.tags.filesystem)
      }
sinks:
  prometheus_remote_write:
    type: prometheus_remote_write
    inputs:
    - host_metrics_relabel
    endpoint: http://127.0.0.1:38086/api/v1/prometheus
    healthcheck:
      enabled: false

```

抓取 kubernetes 指标
```yaml
secret:
  kube_token:
    type: directory
    path: /var/run/secrets/kubernetes.io/serviceaccount
sources:
  cadvisor_metrics:
    type: prometheus_scrape
    endpoints:
    - https://${K8S_NODE_IP_FOR_DEEPFLOW}:10250/metrics/cadvisor
    auth:
      strategy: bearer
      token: SECRET[kube_token.token]
    scrape_interval_secs: 10
    scrape_timeout_secs: 10
    honor_labels: true
    instance_tag: instance
    endpoint_tag: metrics_endpoint
    tls:
      verify_certificate: false
  kubelet_metrics:
    type: prometheus_scrape
    endpoints:
    - https://${K8S_NODE_IP_FOR_DEEPFLOW}:10250/metrics
    auth:
      strategy: bearer
      token: SECRET[kube_token.token]
    scrape_interval_secs: 10
    scrape_timeout_secs: 10
    honor_labels: true
    instance_tag: instance
    endpoint_tag: metrics_endpoint
    tls:
      verify_certificate: false
  kube_state_metrics:
    type: prometheus_scrape
    endpoints:
    - http://opensource-kube-state-metrics:8080/metrics
    scrape_interval_secs: 10
    scrape_timeout_secs: 10
    honor_labels: true
    instance_tag: instance
    endpoint_tag: metrics_endpoint
transforms:
  cadvisor_relabel_filter:
    type: filter
    inputs:
    - cadvisor_metrics
    condition: "!match(string!(.name), r'container_cpu_(cfs_throttled_seconds_total|load_average_10s|system_seconds_total|user_seconds_total)|container_fs_(io_current|io_time_seconds_total|io_time_weighted_seconds_total|reads_merged_total|sector_reads_total|sector_writes_total|writes_merged_total)|container_memory_(mapped_file|swap)|container_(file_descriptors|tasks_state|threads_max)')"
  kubelet_relabel_filter:
    type: filter
    inputs:
    - kubelet_metrics
    condition: "match(string!(.name), r'kubelet_cgroup_(manager_duration_seconds_bucket|manager_duration_seconds_count)|kubelet_node_(config_error|node_name)|kubelet_pleg_relist_(duration_seconds_bucket|duration_seconds_count|interval_seconds_bucket)|kubelet_pod_(start_duration_seconds_count|worker_duration_seconds_bucket|worker_duration_seconds_count)|kubelet_running_(container_count|containers|pod_count|pods)|kubelet_runtime_(operations_duration_seconds_bucket|perations_errors_total|operations_total)|kubelet_volume_stats_(available_bytes|capacity_bytes|inodes|inodes_used)|process_(cpu_seconds_total|resident_memory_bytes)|rest_client_(request_duration_seconds_bucket|requests_total)|storage_operation_(duration_seconds_bucket|duration_seconds_count|errors_total)|up|volume_manager_total_volumes')"
  kube_state_relabel_filter:
    type: filter
    inputs:
    - kube_state_metrics
    condition: "!match(string!(.name), r'kube_endpoint_address_not_ready|kube_endpoint_address_available')"
  common_relabel_config:
    type: remap
    inputs:
    - cadvisor_relabel_filter
    - kubelet_relabel_filter
    - kube_state_relabel_filter
    source: |-
      if !is_null(.tags) && is_string(.tags.metrics_endpoint) {
      .tags.metrics_path = parse_regex!(.tags.metrics_endpoint, r'https?:\/\/[^\/]+(?<path>\/.*)$').path
      }
sinks:
  prometheus_remote_write:
    type: prometheus_remote_write
    inputs:
    - common_relabel_config
    endpoint: http://127.0.0.1:38086/api/v1/prometheus
    healthcheck:
      enabled: false

```

抓取 kubernetes 日志(以采集 DeepFlow Pod 日志为例，若需要采集其他 Pod 日志可修改 `extra_label_selector` 并加上具体条件)
```yaml
data_dir: /vector-log-checkpoint
sources:
  kubernetes_logs:
    self_node_name: ${K8S_NODE_NAME_FOR_DEEPFLOW}
    type: kubernetes_logs
    namespace_annotation_fields:
      namespace_labels: ""
    node_annotation_fields:
      node_labels: ""
    pod_annotation_fields:
      pod_annotations: ""
      pod_labels: ""
    extra_label_selector: "app=deepflow,component!=front-end"
  kubernetes_logs_frontend:
    self_node_name: ${K8S_NODE_NAME_FOR_DEEPFLOW}
    type: kubernetes_logs
    namespace_annotation_fields:
      namespace_labels: ""
    node_annotation_fields:
      node_labels: ""
    pod_annotation_fields:
      pod_annotations: ""
      pod_labels: ""
    extra_label_selector: "app=deepflow,component=front-end"
transforms:
  multiline_kubernetes_logs:
    type: reduce
    inputs:
      - kubernetes_logs
    group_by:
      - file
      - stream
    merge_strategies:
      message: concat_newline
    starts_when: match(string!(.message), r'^(.+=|\[|\[?\u001B\[[0-9;]*m|\[mysql\]\s|\{\".+\"|(::ffff:)?([0-9]{1,3}.){3}[0-9]{1,3}[\s\-]+(\[)?)?\d{4}[-\/\.]?\d{2}[-\/\.]?\d{2}[T\s]?\d{2}:\d{2}:\d{2}')
    expire_after_ms: 2000
    flush_period_ms: 500
  flush_kubernetes_logs:
   type: remap
   inputs:
     - multiline_kubernetes_logs
   source: |-
       .message = replace(string!(.message), r'\u001B\[([0-9]{1,3}(;[0-9]{1,3})*)?m', "")
  remap_kubernetes_logs:
    type: remap
    inputs:
    - flush_kubernetes_logs
    - kubernetes_logs_frontend
    source: |-
        if is_string(.message) && is_json(string!(.message)) {
            tags = parse_json(.message) ?? {}
            ._df_log_type = tags._df_log_type
            .org_id = to_int(tags.org_id) ?? 0
            .user_id = to_int(tags.user_id) ?? 0
            .message = tags.message || tags.msg
            del(tags._df_log_type)
            del(tags.org_id)
            del(tags.user_id)
            del(tags.message)
            del(tags.msg)
            .json = tags
        }
        if !exists(.level) {
           if exists(.json) {
              .level = to_string!(.json.level)
              del(.json.level)
           } else {
             level_tags = parse_regex(.message, r'[\[\\<](?<level>(?i)INFOR?(MATION)?|WARN(ING)?|DEBUG?|ERROR?|TRACE|FATAL|CRIT(ICAL)?)[\]\\>]') ?? {}
             if !exists(level_tags.level) {
                level_tags = parse_regex(.message, r'[\s](?<level>INFOR?(MATION)?|WARN(ING)?|DEBUG?|ERROR?|TRACE|FATAL|CRIT(ICAL)?)[\s]') ?? {}
             }
             if exists(level_tags.level) {
                level_tags.level = upcase(string!(level_tags.level))
                if level_tags.level == "INFORMATION" || level_tags.level == "INFOMATION" {
                    level_tags.level = "INFO"
                }
                if level_tags.level == "WARNING" {
                    level_tags.level = "WARN"
                }
                if level_tags.level == "DEBU" {
                    level_tags.level = "DEBUG"
                }
                if level_tags.level == "ERRO" {
                    level_tags.level = "ERROR"
                }
                if level_tags.level == "CRIT" || level_tags.level == "CRITICAL" {
                    level_tags.level = "FATAL"
                }
                .level = level_tags.level
             }
           }
        }
        if !exists(._df_log_type) {
            ._df_log_type = "system"
        }
        if !exists(.app_service) {
            .app_service = .kubernetes.container_name
        }
sinks:
  http:
    type: http
    inputs: [remap_kubernetes_logs]
    uri: http://127.0.0.1:38086/api/v1/log
    encoding:
      codec: json

```

使用 http_client 或者 socket 拨测一个远端服务
```yaml
sources:
  http_client_dial:
    type: http_client
    endpoint: http://$HOST:$PORT
    method: GET
    scrape_interval_secs: 10
    scrape_timeout_secs: 5
  internal_metrics:
    type: internal_metrics
    scrape_interval_secs: 10
    namespace: ${K8S_NAMESPACE_FOR_DEEPFLOW}
  socket_dial_input:
    type: demo_logs
    interval: 10
    format: shuffle
    lines: [""]
transforms:
  internal_metrics_relabel:
    type: remap
    inputs:
    - internal_metrics
    source: |-
      .tags.instance = "${K8S_NODE_IP_FOR_DEEPFLOW}"
  internal_metrics_dispatch:
    type: route
    inputs:
    - internal_metrics_relabel
    route:
      http_client_dial_metrics: '.tags.component_id == "http_client_dial"'
      socket_dial_metrics: '.tags.component_id == "socket_dial"'
  http_client_dial_metrics:
    type: filter
    inputs:
    - internal_metrics_dispatch.http_client_dial_metrics
    condition: "match(string!(.name),r'http_client_.*')"
  socket_dial_metrics:
    type: filter
    inputs:
    - internal_metrics_dispatch.socket_dial_metrics
    condition: "match(string!(.name),r'buffer.*')"
sinks:
  socket_dial:
    type: socket
    inputs:
    - socket_dial_input
    address: $HOST:$PORT
    mode: tcp
    encoding:
      codec: raw_message
  prometheus_remote_write:
    type: prometheus_remote_write
    inputs:
    - http_client_dial_metrics
    - socket_dial_metrics
    endpoint: http://127.0.0.1:38086/api/v1/prometheus
    healthcheck:
      enabled: false

```

# 处理器 {#processors}

## Packet {#processors.packet}

### Policy {#processors.packet.policy}

#### Fast-path 字典大小 {#processors.packet.policy.fast_path_map_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.fast_path_map_size`

Upgrade from old version: `static_config.fast-path-map-size`

**默认值**:
```yaml
processors:
  packet:
    policy:
      fast_path_map_size: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 10000000] |

**详细描述**:

设置为`0`时，deepflow-agent 根据 `global.limits.max_memory` 参数自动调整 Fast-path 字典大小。
注意：实践中不应配置小于 8000 的值。

#### 禁用 Fast-path {#processors.packet.policy.fast_path_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.fast_path_disabled`

Upgrade from old version: `static_config.fast-path-disabled`

**默认值**:
```yaml
processors:
  packet:
    policy:
      fast_path_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

设置为 `true` 时，deepflow-agent 不启用 fast path。

#### Forward 表容量 {#processors.packet.policy.forward_table_capacity}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.forward_table_capacity`

Upgrade from old version: `static_config.forward-capacity`

**默认值**:
```yaml
processors:
  packet:
    policy:
      forward_table_capacity: 16384
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [16384, 64000000] |

**详细描述**:

转发表大小，用来存储 MAC-IP 信息，调大该参数，deepflow-agent 将消耗更多的内存。

#### 最大 First-path 层级 {#processors.packet.policy.max_first_path_level}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.max_first_path_level`

Upgrade from old version: `static_config.first-path-level`

**默认值**:
```yaml
processors:
  packet:
    policy:
      max_first_path_level: 8
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 16] |

**详细描述**:

DDBS 算法等级。

该配置越大内存开销越小，但是性能会降低。

### TCP 包头（时序图） {#processors.packet.tcp_header}

#### Block 大小 {#processors.packet.tcp_header.block_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.tcp_header.block_size`

Upgrade from old version: `static_config.packet-sequence-block-size`

**默认值**:
```yaml
processors:
  packet:
    tcp_header:
      block_size: 256
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [16, 8192] |

**详细描述**:

压缩和保存多个 TCP 包头的缓冲区大小。

#### Sender 队列大小 {#processors.packet.tcp_header.sender_queue_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.tcp_header.sender_queue_size`

Upgrade from old version: `static_config.packet-sequence-queue-size`

**默认值**:
```yaml
processors:
  packet:
    tcp_header:
      sender_queue_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

TCP 包时序数据的单个发送队列的大小。

#### 包头字段 Flag {#processors.packet.tcp_header.header_fields_flag}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.tcp_header.header_fields_flag`

Upgrade from old version: `static_config.packet-sequence-flag`

**默认值**:
```yaml
processors:
  packet:
    tcp_header:
      header_fields_flag: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 255] |

**详细描述**:

使用一个 8 bit 的 flag 对 deepflow-agent 采集上报的 TCP 报文时序数据内容进行控制，不同
的 bit 位代表不同 TCP 字段的采集开关：
```
| FLAG | SEQ | ACK | PAYLOAD_SIZE | WINDOW_SIZE | OPT_MSS | OPT_WS | OPT_SACK |
    7     6     5              4             3         2        1          0
```
flag 设置为`0`表示全部关闭，设置为`255`表示全部

### PCAP 字节流 {#processors.packet.pcap_stream}

#### Receiver 队列大小 {#processors.packet.pcap_stream.receiver_queue_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.receiver_queue_size`

Upgrade from old version: `static_config.pcap.queue-size`

**默认值**:
```yaml
processors:
  packet:
    pcap_stream:
      receiver_queue_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

设置 deepflow-agent 的 1-mini-meta-packet-to-pcap 队列大小。

#### Sender 队列大小 {#processors.packet.pcap_stream.sender_queue_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.sender_queue_size`

**默认值**:
```yaml
processors:
  packet:
    pcap_stream:
      sender_queue_size: 8192
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [4096, 64000000] |

**详细描述**:

设置 deepflow-agent 的 2-pcap-batch-to-sender 队列大小。

#### 每个 Flow 的缓冲区大小 {#processors.packet.pcap_stream.buffer_size_per_flow}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.buffer_size_per_flow`

Upgrade from old version: `static_config.pcap.flow-buffer-size`

**默认值**:
```yaml
processors:
  packet:
    pcap_stream:
      buffer_size_per_flow: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [64, 64000000] |

**详细描述**:

按流的 PCap 缓冲区大小。到达该值时 flush 该条流的 PCap 数据。

#### 总体缓冲区大小 {#processors.packet.pcap_stream.total_buffer_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.total_buffer_size`

Upgrade from old version: `static_config.pcap.buffer-size`

**默认值**:
```yaml
processors:
  packet:
    pcap_stream:
      total_buffer_size: 88304
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

PCap 总缓冲区大小。到达该值时 flush 所有流的 PCap 数据。

#### Flush 间隔 {#processors.packet.pcap_stream.flush_interval}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.flush_interval`

Upgrade from old version: `static_config.pcap.flush-interval`

**默认值**:
```yaml
processors:
  packet:
    pcap_stream:
      flush_interval: 1m
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '10m'] |

**详细描述**:

如果一条流的 PCap buffer 超过这个时间没有进行过 flush，强制触发一次 flush。

### TOA (TCP Option Address) {#processors.packet.toa}

#### Sender 队列大小 {#processors.packet.toa.sender_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.toa.sender_queue_size`

Upgrade from old version: `static_config.toa-sender-queue-size`

**默认值**:
```yaml
processors:
  packet:
    toa:
      sender_queue_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

以下队列的大小：
- 1-socket-sync-toa-info-queue

#### Cache 大小 {#processors.packet.toa.cache_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.toa.cache_size`

Upgrade from old version: `static_config.toa-lru-cache-size`

**默认值**:
```yaml
processors:
  packet:
    toa:
      cache_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 64000000] |

**详细描述**:

TCP Option Address 信息缓存大小。

## 调用日志 {#processors.request_log}

### 应用协议推断 {#processors.request_log.application_protocol_inference}

#### 推断重试最大次数 {#processors.request_log.application_protocol_inference.inference_max_retries}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_max_retries`

Upgrade from old version: `static_config.l7-protocol-inference-max-fail-count`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_max_retries: 128
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 10000] |

**详细描述**:

Agent 通过一张哈希表记录每一个服务端的应用协议解析结果，包括协议、持续解析失败次数、最后一次解析时间。

当一条 Flow 的应用协议从未成功解析过时，使用哈希表决定尝试解析哪些协议：
- 若没有在哈希表中查到结果，或者查到的结果不可用（协议未知，或失败次数超限，或时间距当前超过 inference_result_ttl）
  - 若失败次数已经超限，则将 Flow 标记为禁止解析，禁止期为 inference_result_ttl
  - 否则，遍历所有开启的应用协议，尝试解析
    - 解析成功时会将协议、解析时间、失败次数（0）更新到哈希表中，使得成功的解析结果保鲜
    - 解析失败时会将解析时间和失败次数（+1）更新到哈希表中，使得失败的尝试能够累计，累计超过阈值后会禁止后续尝试
- 如果在哈希表中查到了具体的、可用的协议，则使用该协议进行尝试
  - 解析成功时会将协议、解析时间、失败次数（0）更新到哈希表中，使得成功的解析结果保鲜
  - 解析失败时会将解析时间和失败次数（+1）更新到哈希表中，使得失败的尝试能够累计，累计超过阈值后会禁止后续尝试

当 Flow 一旦成功解析过一次，后续都仅使用该协议类型尝试解析，且无需再查询哈希表。
每次解析成功时，将会更新哈希表中的协议（针对 HTTP2/gRPC 需进行更新）、解析时间、失败次数。

#### 推断结果 TTL {#processors.request_log.application_protocol_inference.inference_result_ttl}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_result_ttl`

Upgrade from old version: `static_config.l7-protocol-inference-ttl`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_result_ttl: 60s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1d'] |

**详细描述**:

deepflow-agent 会周期性标记每一个<vpc, ip, protocol, port>四元组承载的应用协议类型，以加速
后续数据的应用协议采集过程。为避免误判，应用协议类型的标记结果会周期性更新。该参数控制应用协议的更
新周期。

#### 推理白名单 {#processors.request_log.application_protocol_inference.inference_whitelist}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.application_protocol_inference.inference_whitelist`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_whitelist:
      - port_list:
        - 15001
        - 15006
        process_name: envoy
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

应用协议端口白名单列表，目前仅支持 eBPF 流量。当 eBPF 数据在白名单列表中时，不会再使用应用表查询应用协议，
对应的应用协议通过轮训目前所有支持的协议来获取，白名单数据过多会降低 eBPF 数据的处理性能。

配置键：
- process_name: 进程名称，不支持正则表达式
- port_list: 端口白名单列表

##### 进程名称 {#processors.request_log.application_protocol_inference.inference_whitelist.process_name}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_whitelist.process_name`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_whitelist:
      - process_name: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

进程名称

##### 端口列表 {#processors.request_log.application_protocol_inference.inference_whitelist.port_list}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_whitelist.port_list`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_whitelist:
      - port_list: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

端口列表

#### 启用协议列表 {#processors.request_log.application_protocol_inference.enabled_protocols}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.enabled_protocols`

Upgrade from old version: `static_config.l7-protocol-enabled`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      enabled_protocols:
      - HTTP
      - HTTP2
      - MySQL
      - Redis
      - Kafka
      - DNS
      - TLS
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 仅对列表内的应用协议进行数据采集。通过该参数可以控制 agent 的数据采集范围以
降低资源消耗。

#### 协议特殊配置 {#processors.request_log.application_protocol_inference.protocol_special_config}

##### Oracle {#processors.request_log.application_protocol_inference.protocol_special_config.oracle}

###### Integer 字节序 {#processors.request_log.application_protocol_inference.protocol_special_config.oracle.is_be}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.oracle.is_be`

Upgrade from old version: `static_config.oracle-parse-config.is-be`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        oracle:
          is_be: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

如果环境中 Oracle 整数编码采用大端字节序，则开启此开关。

###### Integer 压缩 {#processors.request_log.application_protocol_inference.protocol_special_config.oracle.int_compressed}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.oracle.int_compressed`

Upgrade from old version: `static_config.oracle-parse-config.int-compress`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        oracle:
          int_compressed: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

如果环境中 Oracle 整数编码采用压缩，则开启此开关。

###### 0x04 响应携带额外字节 {#processors.request_log.application_protocol_inference.protocol_special_config.oracle.resp_0x04_extra_byte}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.oracle.resp_0x04_extra_byte`

Upgrade from old version: `static_config.oracle-parse-config.resp-0x04-extra-byte`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        oracle:
          resp_0x04_extra_byte: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

在不同的 Oracle 版本中，ID 为 0x04 的响应会有不同的数据结构，如果环境中该响应数据的
`影响行数`前有 1byte 的额外数据，请开启此开关。

##### ISO8583 {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583}

###### 数据翻译 {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583.translation_enabled}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.iso8583.translation_enabled`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        iso8583:
          translation_enabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

是否对解析后的数据进行查表翻译后展示。

  - 支持翻译的字段列表:

|  支持翻译的字段       | 示例（翻译前）|示例（翻译后）          | 备注         |
|-----------------------|-------------- |----------------------- |--------------|
| 0-报文类型标识符      | 0100          | 0100-授权类请求        |              |
| 3-交易处理码          | 300000        | 300000-余额查询        |              |
| 32-受理机构标识码     | 6100****      | 6100-中国邮政储蓄银行  | 翻译前4位    |
| 39-应答码             | 00            | 00-承兑或交易成功      |              |
| 49-交易货币代码       | 156           | 156-人民币元           |              |

###### 卡号脱敏 {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583.pan_obfuscate}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.iso8583.pan_obfuscate`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        iso8583:
          pan_obfuscate: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

是否对卡号脱敏。

###### 提取字段 {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583.extract_fields}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.iso8583.extract_fields`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        iso8583:
          extract_fields: 2,7,11,32,33
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

提取字段展示在`数据原生标签`
  - 配置样例: `extract_fields: 0,2-33`

字段对照表:

| 字段号 | 说明 |
|--------|----------|
| 0  | 报文类型标识符 |
| 1  | 位图 |
| 2  | 主账号 |
| 3  | 交易处理码 |
| 4  | 交易金额 |
| 5  | 清算金额 |
| 6  | 持卡人扣账金额 |
| 7  | 交易传输时间 |
| 9  | 清算汇率 |
| 10 | 持卡人扣账汇率 |
| 11 | 系统跟踪号 |
| 12 | 受卡方所在地时间 |
| 13 | 受卡方所在地日期 |
| 14 | 卡有效期 |
| 15 | 清算日期 |
| 16 | 兑换日期 |
| 18 | 商户类型 |
| 19 | 商户国家代码 |
| 22 | 服务点输入方式码 |
| 23 | 卡序列号 |
| 25 | 服务点条件码 |
| 26 | 服务点 PIN 获取码 |
| 28 | 交易费 |
| 32 | 受理机构标识码 |
| 33 | 发送机构标识码 |
| 35 | 第二磁道数据 |
| 36 | 第三磁道数据 |
| 37 | 检索参考号 |
| 38 | 授权标识应答码 |
| 39 | 应答码 |
| 41 | 受卡机终端标识码 |
| 42 | 受卡方标识码 |
| 43 | 受卡方名称地址 |
| 44 | 附加响应数据 |
| 45 | 第一磁道数据 |
| 48 | 附加数据－私有 |
| 49 | 交易货币代码 |
| 50 | 清算货币代码 |
| 51 | 持卡人账户货币代码 |
| 52 | 个人标识码数据 |
| 53 | 安全控制信息 |
| 54 | 实际余额 |
| 55 | IC 卡数据域 |
| 56 | 附加信息 |
| 57 | 附加交易信息 |
| 59 | 明细查询数据 |
| 60 | 自定义域 |
| 61 | 持卡人身份认证信息 |
| 62 | 交换中心数据 |
| 63 | 金融网络数据 |
| 70 | 网络管理信息码 |
| 90 | 原始数据元 |
| 96 | 报文安全码 |
| 100 | 接收机构标识码 |
| 102 | 账户标识 1 |
| 103 | 账户标识 2 |
| 104 | 附加信息 |
| 113 | 附加信息 |
| 116 | 附加信息 |
| 117 | 附加信息 |
| 121 | CUPS 保留 |
| 122 | 受理方保留 |
| 123 | 发卡方保留 |
| 125 | 附加信息 |
| 126 | 附加信息 |
| 128 | 报文鉴别码 |

##### MySQL {#processors.request_log.application_protocol_inference.protocol_special_config.mysql}

###### 解压 MySQL 数据包 {#processors.request_log.application_protocol_inference.protocol_special_config.mysql.decompress_payload}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.mysql.decompress_payload`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        mysql:
          decompress_payload: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

部分 MySQL 数据包采用 LZ77 压缩，开启此选项后，agent 在解析时会对数据包进行解压。
设置为 false 以关闭解压，提升性能。
参考：[MySQL Source Code Documentation](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_compression.html)

##### Grpc {#processors.request_log.application_protocol_inference.protocol_special_config.grpc}

###### 开启解析 gRPC stream 数据 {#processors.request_log.application_protocol_inference.protocol_special_config.grpc.streaming_data_enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.grpc.streaming_data_enabled`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        grpc:
          streaming_data_enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后所有 gRPC 数据包都认为是 `stream` 类型，并且会将 `data` 类型数据包上报，同时延迟计算的响应使用带有 `grpc-status` 字段的。

#### 自定义协议解析 {#processors.request_log.application_protocol_inference.custom_protocols}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.custom_protocols`

**默认值**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      custom_protocols: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

自定义协议解析配置，支持通过简单的规则识别用户自定义的 L7 协议。
示例：
```yaml
- protocol_name: "your_protocol_name" # 协议名称，对应 l7_flow_log.l7_protocol_str，注意：必须存在一个 `processors.request_log.tag_extraction.custom_field_policies` 配置，否则无法上报识别结果
  pre_filter:
    port_list: 1-65535 # 预过滤端口，可以提高解析性能
  request_characters:  # 多个特征之间是 OR 的关系
    - character: # 多个 match_keyword 之间是 AND 的关系
      - match_keyword: abc  # 特征字符串
        match_type: "string" # 取值："string", "hex"
        match_ignore_case: false # 匹配特征字符串是否忽略大小写，当 match_type == string 时生效，默认值: false
        match_from_begining: false # 是否需要从 Payload 头部开始匹配
  response_characters:
    - character:
      - match_keyword: 0123af
        match_type: "hex"
        match_from_begining: false
```

### 过滤器 {#processors.request_log.filters}

#### 端口号预过滤器 {#processors.request_log.filters.port_number_prefilters}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.port_number_prefilters`

Upgrade from old version: `static_config.l7-protocol-ports`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      port_number_prefilters:
        AMQP: 1-65535
        Custom: 1-65535
        DNS: 53,5353
        Dubbo: 1-65535
        FastCGI: 1-65535
        HTTP: 1-65535
        HTTP2: 1-65535
        ISO8583: 1-65535
        Kafka: 1-65535
        MQTT: 1-65535
        Memcached: 11211
        MongoDB: 1-65535
        MySQL: 1-65535
        NATS: 1-65535
        OpenWire: 1-65535
        Oracle: 1521
        PING: 1-65535
        PostgreSQL: 1-65535
        Pulsar: 1-65535
        Redis: 1-65535
        RocketMQ: 1-65535
        SofaRPC: 1-65535
        SomeIP: 1-65535
        TLS: 443,6443
        Tars: 1-65535
        WebSphereMQ: 1-65535
        ZMTP: 1-65535
        bRPC: 1-65535
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

配置样例:
```
HTTP: 80,1000-2000
HTTP2: 1-65535
```

注意：
1. 该参数中，HTTP2 和 TLS 协议的配置仅对 Kprobe 有效，对 Uprobe 无效；
   - 支持协议：[https://www.deepflow.io/docs/zh/features/l7-protocols/overview/](https://www.deepflow.io/docs/zh/features/l7-protocols/overview/)
   - <mark>Oracle 和 TLS 仅在企业版中支持。</mark>
2. 如需控制 `gRPC` 协议，请使用 `HTTP2` 配置。

#### Tag 过滤器 {#processors.request_log.filters.tag_filters}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters`

Upgrade from old version: `static_config.l7-log-blacklist`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        AMQP: []
        Custom: []
        DNS: []
        Dubbo: []
        FastCGI: []
        HTTP: []
        HTTP2: []
        ISO8583: []
        Kafka: []
        MQTT: []
        Memcached: []
        MongoDB: []
        MySQL: []
        NATS: []
        OpenWire: []
        Oracle: []
        PING: []
        PostgreSQL: []
        Pulsar: []
        Redis: []
        RocketMQ: []
        SOFARPC: []
        SomeIP: []
        TLS: []
        Tars: []
        WebSphereMQ: []
        ZMTP: []
        bRPC: []
        gRPC: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

控制不同应用协议数据采集时的 Tag。协议名不区分大小写。
Tag filter 配置例子:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
          - field_name: request_resource  # endpoint, request_type, request_domain, request_resource
            operator: equal               # equal, prefix
            value: somevalue
        HTTP2: []
        # 其他协议
```

##### $HTTP Tag 过滤器 {#processors.request_log.filters.tag_filters.HTTP}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

HTTP Tag filter example:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
          - field_name: request_resource  # endpoint, request_type, request_domain, request_resource
            operator: equal               # equal, prefix
            value: somevalue
```
A l7_flow_log tag_filter can be configured for each protocol, preventing request logs matching
the blacklist from being collected by the agent or included in application performance metrics.
It's recommended to only place non-business request logs like heartbeats or health checks in this
blacklist. Including business request logs might lead to breaks in the distributed tracing tree.

Supported protocols: https://www.deepflow.io/docs/features/l7-protocols/overview/

<mark>Oracle and TLS is only supported in the Enterprise Edition.</mark>

###### 字段名 {#processors.request_log.filters.tag_filters.HTTP.field_name}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP.field_name`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol.field-name`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
        - field_name: ''
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| endpoint | |
| request_type | |
| request_domain | |
| request_resource | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

匹配字段名

###### 匹配操作符 {#processors.request_log.filters.tag_filters.HTTP.operator}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP.operator`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol.operator`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
        - operator: ''
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| equal | |
| prefix | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

匹配操作符

###### 字段值 {#processors.request_log.filters.tag_filters.HTTP.field_value}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP.field_value`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol.value`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
        - field_value: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

匹配字段值。

#### 不关心的 DNS NXDOMAIN 错误 {#processors.request_log.filters.unconcerned_dns_nxdomain_response_suffixes}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.unconcerned_dns_nxdomain_response_suffixes`

Upgrade from old version: `static_config.l7-protocol-advanced-features.unconcerned-dns-nxdomain-response-suffixes`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      unconcerned_dns_nxdomain_response_suffixes: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，当系统中 DNS 响应异常为 `Non-Existent Domain`，且响应结果中的后缀与参数中的字段
匹配时， deepflow-agent 会将 DNS 响应码置为`0`，响应状态置为`正常`。
该特性用于忽略特定的 `Non-Existent Domain` 类型的 DNS 响应，比如 K8s Pod 解析外部域名时，会将
待解析域名与 cluster 内的域名后缀做拼接并多次尝试解析，因而会产生多次的 `Non-Existent Domain`
的响应结果，干扰数据分析。

#### cBPF data disabled {#processors.request_log.filters.cbpf_disabled}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.filters.cbpf_disabled`

**默认值**:
```yaml
processors:
  request_log:
    filters:
      cbpf_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

关闭后 deepflow-agent 将停止从 packet 数据生成调用日志。

### 超时设置 {#processors.request_log.timeouts}

#### TCP 调用超时时间 {#processors.request_log.timeouts.tcp_request_timeout}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.timeouts.tcp_request_timeout`

Upgrade from old version: `static_config.rrt-tcp-timeout`

**默认值**:
```yaml
processors:
  request_log:
    timeouts:
      tcp_request_timeout: 300s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '3600s'] |

**详细描述**:

deepflow-agent 采集 TCP 承载的应用调用时等待响应消息的最大时长，如果响应与请求之间的时间差超过
该参数值，该次调用将被识别为超时。该参数需大于配置 `processors.request_log.timeouts.session_aggregate`
中 TCP 类型的超时时间（例如 HTTP2 默认值 120s），并小于 3600s。

#### UDP 调用超时时间 {#processors.request_log.timeouts.udp_request_timeout}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.timeouts.udp_request_timeout`

Upgrade from old version: `static_config.rrt-udp-timeout`

**默认值**:
```yaml
processors:
  request_log:
    timeouts:
      udp_request_timeout: 150s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '300s'] |

**详细描述**:

deepflow-agent 采集 UDP 承载的应用调用时等待响应消息的最大时长，如果响应与请求之间的时间差超过该参数值，该次调用将被识别为超时。
该参数需大于配置 `processors.request_log.timeouts.session_aggregate` 中 UDP 类型的超时时间（例如 DNS 默认值 15s），并小于 300s。

#### 会话合并窗口时长 {#processors.request_log.timeouts.session_aggregate_window_duration}

**标签**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`processors.request_log.timeouts.session_aggregate_window_duration`

Upgrade from old version: `static_config.l7-log-session-aggr-timeout`

**默认值**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate_window_duration: 120s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['20s', '300s'] |

**详细描述**:

应用调用日志请求、响应合并的时间窗口，超出该时间窗口的响应将不与请求合并，而是单独生成一条调用日志。

#### 应用会话合并超时设置 {#processors.request_log.timeouts.session_aggregate}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.timeouts.session_aggregate`

**默认值**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

设置每个应用的超时时间。
DNS 和 TLS 默认 15s，其他协议默认 120s。

示例:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate:
      - protocol: DNS
        timeout: 15s
      - protocol: HTTP2
        timeout: 120s
```

##### 协议 {#processors.request_log.timeouts.session_aggregate.protocol}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.timeouts.session_aggregate.protocol`

**默认值**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate:
      - protocol: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

用于设置超时时间的协议名称。

##### 超时时间 {#processors.request_log.timeouts.session_aggregate.timeout}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.timeouts.session_aggregate.timeout`

**默认值**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate:
      - timeout: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |

**详细描述**:

设置应用的超时时间。TCP 类型的应用协议超时时间需要小于 `processors.request_log.timeouts.tcp_request_timeout`，
UDP 类型的应用协议超时时间需要小于 `processors.request_log.timeouts.udp_request_timeout`。

### 标签提取 {#processors.request_log.tag_extraction}

#### Tracing 标签 {#processors.request_log.tag_extraction.tracing_tag}

##### HTTP 真实客户端 {#processors.request_log.tag_extraction.tracing_tag.http_real_client}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.http_real_client`

Upgrade from old version: `http_log_proxy_client`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        http_real_client:
        - X_Forwarded_For
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，deepflow-agent 会尝试从 HTTP header 中匹配特征字段，并将匹配到
的结果填充到应用调用日志的`http_proxy_client`字段中，作为调用链追踪的特征值。
如果指定多个值，优先级从前到后降低。插件重写的字段优先级最高。

##### X-Request-ID {#processors.request_log.tag_extraction.tracing_tag.x_request_id}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.x_request_id`

Upgrade from old version: `http_log_x_request_id`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        x_request_id:
        - X_Request_ID
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，deepflow-agent 会尝试从 HTTP header 中匹配特征字段，并将匹配到
的结果填充到应用调用日志的`x_request_id`字段中，作为调用链追踪的特征值。
如果指定多个值，优先级从前到后降低。插件重写的字段优先级最高。

##### 多 TraceID 采集 {#processors.request_log.tag_extraction.tracing_tag.multiple_trace_id_collection}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.multiple_trace_id_collection`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        multiple_trace_id_collection: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

- 配置为 `false` 时，根据配置 `APM TraceID` 采集到第一个匹配的 TraceID 就不继续采集。
- 配置为 `true` 时，采集所有匹配到的 TraceID。

##### APM TraceID {#processors.request_log.tag_extraction.tracing_tag.apm_trace_id}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.apm_trace_id`

Upgrade from old version: `http_log_trace_id`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        apm_trace_id:
        - traceparent
        - sw8
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，deepflow-agent 会尝试从 HTTP 和 RPC header 中匹配特征字段，并将匹配到
的结果填充到应用调用日志的`trace_id`字段中，作为调用链追踪的特征值。参数支持填写多个不同的
特征字段，中间用`,`分隔。
如果指定多个值，优先级从前到后降低。插件重写的字段优先级最高。

##### Copy APM TraceID {#processors.request_log.tag_extraction.tracing_tag.copy_apm_trace_id}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.copy_apm_trace_id`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        copy_apm_trace_id: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

设置为 true 时，将会抄写 APM TraceID 至 attribute.apm_trace_id 字段中。

##### APM SpanID {#processors.request_log.tag_extraction.tracing_tag.apm_span_id}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.apm_span_id`

Upgrade from old version: `http_log_span_id`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        apm_span_id:
        - traceparent
        - sw8
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，deepflow-agent 会尝试从 HTTP 和 RPC header 中匹配特征字段，并将匹配到
的结果填充到应用调用日志的`span_id`字段中，作为调用链追踪的特征值。参数支持填写多个不同的
特征字段，中间用`,`分隔。
如果指定多个值，优先级从前到后降低。插件重写的字段优先级最高。

#### HTTP 端点 {#processors.request_log.tag_extraction.http_endpoint}

##### 禁用提取 {#processors.request_log.tag_extraction.http_endpoint.extraction_disabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.extraction_disabled`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.disabled`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        extraction_disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

默认值为`false`，表示开启 HTTP 协议的 endpoint 提取功能；设置为`true`时，表示关闭该功能。

##### 匹配规则 {#processors.request_log.tag_extraction.http_endpoint.match_rules}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.match_rules`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.match-rules`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        match_rules:
        - keep_segments: 2
          url_prefix: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

HTTP 协议的 endpoint 提取遵循如下规则：
- 最长匹配原则：优先匹配最长的前缀；
- 提取 URL 最前的数段（段数由参数确定，默认值为 2）作为 endpoint。
比如，URL 为 `/a/b/c?query=xxx`，deepflow-agent 默认提取 `/a/b` 作为 endpoint。

###### URL 前缀 {#processors.request_log.tag_extraction.http_endpoint.match_rules.url_prefix}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.match_rules.url_prefix`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.match-rules.prefix`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        match_rules:
        - url_prefix: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

HTTP URL 前缀。

###### 截取 Segment 数 {#processors.request_log.tag_extraction.http_endpoint.match_rules.keep_segments}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.match_rules.keep_segments`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.match-rules.keep-segments`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        match_rules:
        - keep_segments: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

截取 URL 的段数。

#### 自定义字段 {#processors.request_log.tag_extraction.custom_fields}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_fields`

Upgrade from old version: `static_config.l7-protocol-advanced-features.extra-log-fields`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP: []
        HTTP2: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| HTTP | |
| HTTP2 | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

配置 HTTP、HTTP2、gRPC 等协议的额外提取字段。

示例:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: "user-agent"
        - field_name: "cookie"
```

注意：如需配置`gRPC`协议，使用`HTTP2`匹配。

##### $HTTP 自定义字段 {#processors.request_log.tag_extraction.custom_fields.HTTP}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_fields.HTTP`

Upgrade from old version: `static_config.l7-protocol-advanced-features.extra-log-fields.$protocol`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

配置 HTTP、HTTP2、gRPC 等协议的额外提取字段。

示例:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: "user-agent"
        - field_name: "cookie"
```

注意：如需配置`gRPC`协议，使用`HTTP2`。

###### 字段名 {#processors.request_log.tag_extraction.custom_fields.HTTP.field_name}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_fields.HTTP.field_name`

Upgrade from old version: `static_config.l7-protocol-advanced-features.extra-log-fields.$protocol.field-name`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

字段名

#### 自定义字段提取策略 {#processors.request_log.tag_extraction.custom_field_policies}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_field_policies`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_field_policies: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

自定义字段提取策略，用于通过简单的规则提取 L7 协议中可能存在的自定义字段
同时匹配插件和自定义提取策略时，优先级为：
1. 插件提取
2. 自定义字段提取
3. 采集器默认提取
示例：
```yaml
- policy_name: "my_policy" # 策略名称
  protocol_name: HTTP # 协议名称，如要解析 Grpc 请配置为 HTTP2，可选值： HTTP/HTTP2/Dubbo/SofaRPC/Custom/...
  custom_protocol_name: "my_protocol"  # 当 protocol_name 为 Custom 时生效，注意：此时必须存在一个 `processors.request_log.application_protocol_inference.custom_protocols` 配置，且自定义名称协议名称相等，否则无法解析
  filters:
    traffic_direction: both # 在请求、响应或二者中搜索，默认值为 both，可选值 request/response/both
    port_list: 1-65535 # 可以用于过滤端口
    feature_string: "" # 可以用于提取前匹配 Payload，对 header_field 类型无效
  # 是否保存原始数据。
  # 注意该配置仅在满足 filters 的条件下生效。
  raw:
    save_request:
      enabled: false
      output:
        attribute_name: request
    save_response:
      enabled: false
      output:
        attribute_name: response
  fields:
  - name: "my_field" # 字段名，用于 compound_fields 中
    # 字段的提取类型，可选值及含义为：
    # - `http_url_field`：从 HTTP URL 末尾的参数中提取字段，URL 末尾形如：`?key=value&key2=value2`
    # - `header_field`：从 HTTP/Dubbo/SofaRPC/...等协议的 Header 部分提取字段，例如 HTTP 的 Header 形如：`key: value`
    # - `payload_json_value`：从 Json Payload 中提取字段，形如：`"key": 1`,  或者 `"key": "value"`,  或者 `"key": None`, 等等 ...
    # - `payload_xml_value`：从 XML Payload 中提取字段，形如：`<key attr="xxx">value</key>`
    # - `payload_hessian2_value`：Payload 使用 Hessian2 编码，从中提取字段
    # - `sql_insertion_column`：从 SQL 插入列中提取字段，例如：`INSERT INTO table (column1, column2) VALUES (value1, value2)`。目前只支持 MySQL 协议，且只能提取插入的第一列内容。
    type: "http_url_field"
    # 匹配规则
    match:
      # 匹配类型，可选值："string" 和 "path"
      # 配置为 "string" 时
      # - 对于 http_url_field 和 header_field 匹配 key，对于 sql_insertion_column 匹配 SQL 插入列名
      # - 对于 payload_json_value 和 payload_xml_value 匹配 JSON 和 XML 格式的内容，并取第一个匹配位置后的元素作为结果
      # "path" 类型只对 parse_json_value 和 parse_xml_value 类型的字段有效，可以用 "aaa.bbb.ccc" 这样的语法按层级提取 XML 和 JSON 格式的内容
      type: "string"
      keyword: "abc"
      # 是否忽略大小写，默认值：false，仅当 `type` 为 "string" 时有效
      ignore_case: false
      # 是否对所有叶子节点应用字段规则，默认值：false
      # 该配置只对 parse_json_value 和 parse_xml_value 类型的字段有效
      # 设置为 true 时，字段规则将有以下行为改变：
      # - 对 keyword 匹配 JSON 或 XML 的内容下所有叶子节点应用规则
      # - output 中配置只有 attribute_name 生效，表示输出结果的前缀。输出的名字将使用 attribute_name 作为前缀，后接叶子节点的路径作为后缀，中间以 “.” 分隔
      # - field 将无法用于 compound_fields 中
      all_leaves: false
    # 后处理，注意这里的配置是顺序执行的
    # 配置格式为：
    # - type: post_processing_type
    #   setting:
    #   - key: setting_key
    #     value: setting_value
    # 其中 type 支持的类型为：
    # - remap
    # - obfuscate
    # - url_decode
    # - base64_decode
    # - parse_json_value
    # - parse_xml_value
    # - parse_key_value
    # 各类型具体说明和配置方式见下
    post:
    # remap 用于将提取结果映射为另一个值
    # 支持的配置：
    # - dictionary_name: 字典名称
    - type: remap
      settings:
      - key: dictionary_name
        value: dict_1
    # obfuscate 用于对提取结果进行脱敏处理
    # 支持的配置：
    # - mask: 脱敏用的字符，默认为 *，只支持 ascii 字符
    # - preset: 使用预制的脱敏方式，合法的值有：
    #   - id-card-name 身份证姓名脱敏（只显示名字中第一个字符）
    #   - id-card-number 身份证号码脱敏（只显示前六位和后四位）
    #   - phone-number 电话号码脱敏（隐藏中间不少于四位）
    # - range: 表示从第几个字符到第几个字符替换为 *，即只保留第一个和最后一个字符
    - type: obfuscate
      settings:
      - key: mask
        value: *
      - key: preset
        value: id-card-name
      - key: range
        value: "1, -1" # 表示从第二个字符到倒数第一个字符替换为 *，即只保留第一字
      - key: range # 配置多个代表多范围替换
        value: "6, -5" # 表示第七个字符到倒数第五个字符替换为 *
    # url_decode 用于对提取结果进行 URL 解码
    - type: url_decode
    # base64_decode 用于对提取结果进行 Base64 解码，输出的结果须为合法的 utf-8
    - type: base64_decode
    # parse_json_value 用于对提取结果进行 JSON 解析
    # 支持的配置：
    # - keyword: 关键词
    # - type: 类型，可选值：string/path
    # - ignore_case: 是否忽略大小写，默认值：false
    # - skip: 表示跳过前几个匹配结果，从第几个开始取
    - type: parse_json_value
      settings:
      - key: keyword
        value: xyz
      - key: type
        value: string
      - key: ignore_case
        value: false
      - key: skip
        value: 0
    # parse_xml_value 用于对提取结果进行 XML 解析
    # 支持的配置：
    # - keyword: 关键词
    # - type: 类型，可选值：string/path
    # - ignore_case: 是否忽略大小写，默认值：false
    # - skip: 表示跳过前几个匹配结果，从第几个开始取
    - type: parse_xml_value
      # 这部分配置与 fields -> match 相同，只是拆成 key/value 的形式
      # 额外支持 skip 配置，表示取第几个匹配结果
      settings:
      - key: keyword
        value: xyz
      - key: type
        value: string
      - key: ignore_case
        value: false
      - key: skip
        value: 0
    # parse_key_value 用于对提取结果按键值对解析
    # 支持的配置：
    # - key_value_pair_separator: 键值对分隔符，默认值：","
    # - key_value_separator: 键值分隔符，默认值："="
    # - keyword: 关键词
    # - ignore_case: 是否忽略大小写，默认值：false
    - type: parse_key_value
      settings:
      - key: key_value_pair_separator
        value: ","
      - key: key_value_separator
        value: "="
      - key: keyword
        value: xyz
      - key: ignore_case
        value: true
    # 验证 post 处理后的结果是否合法
    verify:
      check_charset: false # 可用于检查提取结果是否合法
      primary_charset: ["digits", "alphabets", "hanzi"] # 提取结果校验字符集，可选值：digits/alphabets/hanzi
      special_characters: ".-_" # 提取结果校验字符集，额外校验这些特殊字符
    output:
      attribute_name: "xyz" # 此时该字段将会出现在调用日志的 attribute.xyz 中，默认值为空，为空时该字段不会加入到 attribute 内
      metric_name: "xyz" # 此时该字段将会出现在调用日志的 metrics.xyz 中，默认值为空
      rewrite_native_tag:
        # 可以填写以下几种字段之一，用于覆写对应字段的值
        # 注意对应的协议需要支持，否则配置无效
        # 当重写 response_code 时，自动将原来的非空值以 `sys_response_code` 为名写入 attribute 中
        # - version
        # - request_type
        # - request_domain
        # - request_resource
        # - request_id
        # - endpoint
        # - response_code
        # - response_exception
        # - response_result
        # - trace_id
        # - span_id
        # - x_request_id
        # - x_request_id_0
        # - x_request_id_1
        # - http_proxy_client
        # - biz_type
        # - biz_code
        # - biz_scenario
        name: version
        # 映射字典名称，配置不为空时将输入用所配置的字典进行映射。配置为空时不生效
        # 注意：condition 中的黑白名单匹配映射后的结果
        remap: dict_1
        condition:
          enum_whitelist: [] # 枚举白名单，当提取结果在白名单中时，进行重写。配置为空时不生效
          enum_blacklist: [] # 枚举黑名单，当提取结果在黑名单中时，不进行重写
      # 根据提取值匹配下列数组内容，如果匹配到，则将 response_status 设置为对应的值
      rewrite_response_status:
        ok_values: []
        client_error_values: []
        server_error_values: []
        default_status: "" # 可选为 ok/client_error/server_error，设置为空时如果没有匹配则不进行重写。默认值为空
      # 字段输出优先级，默认值为 0，范围 0-255，值越小优先级越高
      # 对于只保留一个值的字段而言（除 trace_id 外），相同的字段只保留值最小的一个
      # 对于多个值的字段（trace_id）而言，按优先级从高到低的顺序进行输出
      priority: 0
  # 直接用常量值作为字段值
  const_fields:
  - value: "123"
    # 输出配置，参考 fields 中 output 的说明进行配置，但不支持 metric，rewrite_response_status 和 rewrite_native_tag 中的 remap/condition
    output:
      attribute_name: "xyz"
      rewrite_native_tag:
        name: version
      priority: 0
  # 复合字段，可以使用配置的 field 或 native_tag 作为输入字段，进行格式化输出
  # 如果未解析到对应的 field 或 native_tag 为空，则不进行输出
  compound_fields:
  - format: "{field1_name}-{field2_name}" # 输出格式，其中 field1_name 和 field2_name 为已配置的字段名
                                          # 也可以配置 native_tag 作为输入字段，但注意已配置字段的优先级更高
    output: # 参考 fields 中 output 的说明进行配置
      attribute_name: "xyz"
      metric_name: "xyz"
      rewrite_native_tag:
        name: version
        remap: dict_1
        condition:
          enum_whitelist: []
          enum_blacklist: []
      rewrite_response_status:
        ok_values: []
        client_error_values: []
        server_error_values: []
        default_status: ""
      priority: 0
  dictionaries:
  - name: dict_1
    entries:
    - key: key1
      value: value1
    - key: key2
      value: value2
    default: value3
```

#### 脱敏协议列表 {#processors.request_log.tag_extraction.obfuscate_protocols}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.obfuscate_protocols`

Upgrade from old version: `static_config.l7-protocol-advanced-features.obfuscate-enabled-protocols`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      obfuscate_protocols:
      - Redis
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| MySQL | |
| PostgreSQL | |
| HTTP | |
| HTTP2 | |
| Redis | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，deepflow-agent 将在采集时对特定应用协议的关键数据做脱敏处理。
脱敏字段主要包括：
- 授权信息
- 各类语句中的 value 信息

#### 原始数据 {#processors.request_log.tag_extraction.raw}

Control the extraction of raw data corresponding to the L7 logs

##### 提取的请求头长度 {#processors.request_log.tag_extraction.raw.error_request_header}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_request_header`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_request_header: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**详细描述**:

当设置为大于 0 的值时，对于状态异常的调用日志，自动采集请求 Header（截断到 $error_request_header 字节）到 attribute.request_header，
因如下原因此功能仅建议临时使用：
- 一方面直接存储 Header 有一定的敏感信息暴露风险，可能导致合规问题
- 另一方面也会导致（目前仅 HTTP 协议）所有 Request Header 被缓存，直到等到解析到 Response 状态才能判断是否发送，消耗采集器资源

##### 提取的请求头长度 {#processors.request_log.tag_extraction.raw.error_response_header}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_response_header`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_response_header: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**详细描述**:

当设置为大于 0 的值时，对于状态异常的调用日志，自动采集响应 Header（截断到 $error_response_header 字节）到 attribute.response_header。

##### 提取的响应头长度 {#processors.request_log.tag_extraction.raw.error_request_payload}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_request_payload`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_request_payload: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**详细描述**:

当设置为大于 0 的值时，对于状态异常的调用日志，自动采集请求 Payload（截断到 $error_request_payload）到
attribute.request_payload，因以下原因此功能仅建议临时使用：
- 一方面直接存储 Payload 有一定的敏感信息暴露风险，可能导致合规问题
- 另一方面也会导致（目前仅 HTTP 协议）所有 Request Payload 被缓存，直到等到解析到 Response 状态才能判断是否发送，
  消耗采集器资源

##### 提取的请求头长度 {#processors.request_log.tag_extraction.raw.error_response_payload}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_response_payload`

**默认值**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_response_payload: 256
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**详细描述**:

默认值为 256，表示采集异常响应 Payload 的前 256 字节，放到 attribute.response_payload 当设置为 0 时，表示不采集
异常响应 Payload

### 调优 {#processors.request_log.tunning}

#### Payload 截取 {#processors.request_log.tunning.payload_truncation}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.tunning.payload_truncation`

Upgrade from old version: `l7_log_packet_size`

**默认值**:
```yaml
processors:
  request_log:
    tunning:
      payload_truncation: 1024
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [256, 65535] |

**详细描述**:

应用调用日志采集解析的最大 payload 长度。注意实际的值小于 `inputs.cbpf.tunning.max_capture_packet_size`。
注意：eBPF 数据的 payload 可解析长度上限为 16384 Byte。

#### 会话聚合桶容量 {#processors.request_log.tunning.session_aggregate_slot_capacity}

**标签**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`processors.request_log.tunning.session_aggregate_slot_capacity`

Upgrade from old version: `static_config.l7-log-session-slot-capacity`

**默认值**:
```yaml
processors:
  request_log:
    tunning:
      session_aggregate_slot_capacity: 1024
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 1000000] |

**详细描述**:

默认情况下，2 分钟缓存窗口中的单向 l7_flow_log 将被聚合成双向的 request_log（会话）。
聚合时的槽位大小为 5 秒。该配置用于指定每个时间槽中最多可以缓存多少个单向的 l7_flow_log 条目。

如果某个时间槽中的 l7_flow_log 条目数量超过该配置，则该时间槽中 10% 的 l7_flow_log 条目将被
LRU 策略淘汰以减少内存占用。注意，被淘汰的 l7_flow_log 条目不会被丢弃，而是作为单向的 request_log
发送给 deepflow-server。

以下指标可以作为调整该配置的参考数据：
- Metric `deepflow_tenant.deepflow_agent_l7_session_aggr.cached-request-resource`
  用于记录当前时刻所有时间槽中缓存的 request_resource 字段占用的总内存，单位为字节。
- Metric `deepflow_tenant.deepflow_agent_l7_session_aggr.over-limit`
  用于记录达到 LRU 容量限制并触发淘汰的次数。

#### 会话聚合最大条目数 {#processors.request_log.tunning.session_aggregate_max_entries}

**标签**:

`hot_update`

**FQCN**:

`processors.request_log.tunning.session_aggregate_max_entries`

**默认值**:
```yaml
processors:
  request_log:
    tunning:
      session_aggregate_max_entries: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [16384, 10000000] |

**详细描述**:

会话聚合最大条目数。
如果 l7_flow_log 条目总数超过该配置，最老的条目将被丢弃，并设置其 response 状态为 `Unknown`。

#### 应用指标时间一致性开关 {#processors.request_log.tunning.consistent_timestamp_in_l7_metrics}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tunning.consistent_timestamp_in_l7_metrics`

**默认值**:
```yaml
processors:
  request_log:
    tunning:
      consistent_timestamp_in_l7_metrics: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当开关打开时对于同一个会话的请求和响应, 它们对应的指标数据会全部统计在请求所在的时间戳里

## 流日志 {#processors.flow_log}

### 时间窗口 {#processors.flow_log.time_window}

#### 最大可容忍的 Packet 延迟 {#processors.flow_log.time_window.max_tolerable_packet_delay}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.time_window.max_tolerable_packet_delay`

Upgrade from old version: `static_config.packet-delay`

**默认值**:
```yaml
processors:
  flow_log:
    time_window:
      max_tolerable_packet_delay: 1s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '20s'] |

**详细描述**:

捕获的包携带的时间戳可能比当前时间晚，尤其是在流量高峰期可能延迟高达 10s。
该配置也会影响 FlowMap 聚合窗口的大小。

#### 额外可容忍的 Flow 延迟 {#processors.flow_log.time_window.extra_tolerable_flow_delay}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.time_window.extra_tolerable_flow_delay`

Upgrade from old version: `static_config.second-flow-extra-delay-second`

**默认值**:
```yaml
processors:
  flow_log:
    time_window:
      extra_tolerable_flow_delay: 0s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0s', '20s'] |

**详细描述**:

QuadrupleGenerator 接收 flow 的额外时间延迟。
该配置会影响秒级和分钟级 QuadrupleGenerator 聚合窗口的大小。

### Conntrack（即 Flow Map） {#processors.flow_log.conntrack}

#### Flow Flush 间隔 {#processors.flow_log.conntrack.flow_flush_interval}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_flush_interval`

Upgrade from old version: `static_config.flow.flush-interval`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_flush_interval: 1s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1m'] |

**详细描述**:

FlowMap 中流产生延迟时间，用于在下游处理单元中增加窗口大小，避免窗口推动过快。

#### Flow 生成逻辑 {#processors.flow_log.conntrack.flow_generation}

##### 服务端口号 {#processors.flow_log.conntrack.flow_generation.server_ports}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.server_ports`

Upgrade from old version: `static_config.server-ports`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        server_ports: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

deepflow-agent 有可能会错误的判断长流的方向，如果某个端口一定是服务端端口，
可配置在此处避免误判断。

##### 云流量忽略 MAC {#processors.flow_log.conntrack.flow_generation.cloud_traffic_ignore_mac}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.cloud_traffic_ignore_mac`

Upgrade from old version: `static_config.flow.ignore-tor-mac`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        cloud_traffic_ignore_mac: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

默认情况下，对云流量采集做流聚合时，deepflow-agent 会校验 MAC 地址，如果同一位置、同一条流的
上、下行数据包中的 MAC 地址不一致（非对称），将导致会话的上、下行数据无法聚合为同一条流。开启此
开关后，deepflow-agent 将在流聚合过程中不校验 MAC 地址。

##### 忽略 L2End {#processors.flow_log.conntrack.flow_generation.ignore_l2_end}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.ignore_l2_end`

Upgrade from old version: `static_config.flow.ignore-l2-end`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        ignore_l2_end: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

对于虚拟网络流量，流聚合仅匹配 l2end 为 true 的一端的 MAC 地址, 设置为 `true`
流聚合会使用全部MAC地址。

##### IDC 流量忽略 VLAN {#processors.flow_log.conntrack.flow_generation.idc_traffic_ignore_vlan}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.idc_traffic_ignore_vlan`

Upgrade from old version: `static_config.flow.ignore-idc-vlan`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        idc_traffic_ignore_vlan: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当在同一位置采集的双向流量的 VLAN 不对称时，流量无法聚合为同一条流。您可以
此时设置此值。仅适用于 IDC（非云）流量。

#### 超时设置 {#processors.flow_log.conntrack.timeouts}

##### Established {#processors.flow_log.conntrack.timeouts.established}

**标签**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.established`

Upgrade from old version: `static_config.flow.established-timeout`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        established: 300s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**详细描述**:

TCP 状态机的建连状态超时时长。

##### Closing RST {#processors.flow_log.conntrack.timeouts.closing_rst}

**标签**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.closing_rst`

Upgrade from old version: `static_config.flow.closing-rst-timeout`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        closing_rst: 35s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**详细描述**:

Closing Reset 类型的 TCP 状态机超时。

##### Opening RST {#processors.flow_log.conntrack.timeouts.opening_rst}

**标签**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.opening_rst`

Upgrade from old version: `static_config.flow.opening-rst-timeout`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        opening_rst: 1s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**详细描述**:

Opening Reset 类型的 TCP 状态机超时。

##### Others {#processors.flow_log.conntrack.timeouts.others}

**标签**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.others`

Upgrade from old version: `static_config.flow.others-timeout`

**默认值**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        others: 5s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**详细描述**:

其他类型的 TCP 状态机超时。

### 调优 {#processors.flow_log.tunning}

#### FlowMap 哈希桶 {#processors.flow_log.tunning.flow_map_hash_slots}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.flow_map_hash_slots`

Upgrade from old version: `static_config.flow.flow-slots-size`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      flow_map_hash_slots: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

由于 FlowAggregator 是所有处理流程的第一步，该值也被广泛用于其他哈希表，如
QuadrupleGenerator、Collector 等。

#### 并发 Flow 数量限制 {#processors.flow_log.tunning.concurrent_flow_limit}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.concurrent_flow_limit`

Upgrade from old version: `static_config.flow.flow-count-limit`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      concurrent_flow_limit: 65535
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

FlowMap 中存储的最大并发 Flow 数量。当 `inputs.cbpf.common.capture_mode` 为 `物理网络镜像` 并且该配置值小于等
于 65535 时，将会被强制设置为 u32::MAX。

#### RRT 缓存容量 {#processors.flow_log.tunning.rrt_cache_capacity}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.rrt_cache_capacity`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      rrt_cache_capacity: 16000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

FlowMap 中 RRT Cache 表的容量。该表用于计算 RRT 延迟指标，过大会导致采集器内存占用高，过小会导致RRT指标缺失。

#### 内存池大小 {#processors.flow_log.tunning.memory_pool_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.memory_pool_size`

Upgrade from old version: `static_config.flow.memory-pool-size`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      memory_pool_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

FlowMap 内存池的大小。

#### Batched Buffer 最大大小 {#processors.flow_log.tunning.max_batched_buffer_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.max_batched_buffer_size`

Upgrade from old version: `static_config.batched-buffer-size-limit`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      max_batched_buffer_size: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

目前只影响 TaggedFlow 批量分配。
为避免大量的 malloc 调用，生命周期短且数量多的结构体用批量分配进行优化。
一次分配的总内存大小不会超过这个限制。
由于默认的 MMAP_THRESHOLD 是 128K，分配的内存块超过 128K 会导致
mmap 调用和页错误增加，反而降低性能，所以不推荐将该配置设置大于 128K。

#### FlowAggregator 队列大小 {#processors.flow_log.tunning.flow_aggregator_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.flow_aggregator_queue_size`

Upgrade from old version: `static_config.flow.flow-aggr-queue-size`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      flow_aggregator_queue_size: 65535
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

以下队列的大小：
- 2-second-flow-to-minute-aggrer

#### FlowGenerator 队列大小 {#processors.flow_log.tunning.flow_generator_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.flow_generator_queue_size`

Upgrade from old version: `static_config.flow-queue-size`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      flow_generator_queue_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

以下队列的大小：
- 1-tagged-flow-to-quadruple-generator
- 1-tagged-flow-to-app-protocol-logs
- 0-{flow_type}-{port}-packet-to-tagged-flow (flow_type: sflow, netflow)

#### QuadrupleGenerator 队列大小 {#processors.flow_log.tunning.quadruple_generator_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.quadruple_generator_queue_size`

Upgrade from old version: `static_config.quadruple-queue-size`

**默认值**:
```yaml
processors:
  flow_log:
    tunning:
      quadruple_generator_queue_size: 262144
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [262144, 64000000] |

**详细描述**:

以下队列的大小：
- 2-flow-with-meter-to-second-collector
- 2-flow-with-meter-to-minute-collector

# 输出 {#outputs}

## Socket {#outputs.socket}

### Data Socket 类型 {#outputs.socket.data_socket_type}

**标签**:

`hot_update`

**FQCN**:

`outputs.socket.data_socket_type`

Upgrade from old version: `collector_socket_type`

**默认值**:
```yaml
outputs:
  socket:
    data_socket_type: TCP
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| TCP | |
| UDP | |
| FILE | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置 deepflow-agent 向 deepflow-server 回传数据所用的 Socket 类型。在独立部署
模式下，需配置为 FILE 类型，agent 将 l4_flow_log 和 l7_flow_log 写入本地文件。

### NPB Socket 类型 {#outputs.socket.npb_socket_type}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.socket.npb_socket_type`

Upgrade from old version: `npb_socket_type`

**默认值**:
```yaml
outputs:
  socket:
    npb_socket_type: RAW_UDP
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| UDP | |
| RAW_UDP | |
| TCP | |
| ZMQ | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

设置 NPB 分发时使用的 Socket 类型。RAW_UDP 使用 RawSocket 发送 UDP 数据，有更高的
分发性能，但是可能存在一些环境不兼容的情况。

### RAW_UDP QoS Bypass {#outputs.socket.raw_udp_qos_bypass}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.socket.raw_udp_qos_bypass`

Upgrade from old version: `static_config.enable-qos-bypass`

**默认值**:
```yaml
outputs:
  socket:
    raw_udp_qos_bypass: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当使用 RAW_UDP 发送数据时，可以开启该特性以提升数据发送的性能。注意：（1）该特性需要
Linux Kernel >= 3.14；（2）特性开启后，发送的数据包无法被 tcpdump 捕获。

### 使用多个 Ingester Socket {#outputs.socket.multiple_sockets_to_ingester}

**标签**:

`hot_update`

**FQCN**:

`outputs.socket.multiple_sockets_to_ingester`

Upgrade from old version: `static_config.multiple-sockets-to-ingester`

**默认值**:
```yaml
outputs:
  socket:
    multiple_sockets_to_ingester: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当设置为 true 时，deepflow-agent 将使用多个套接字将数据发送到 Ingester，
其发送性能更高，但会给防火墙带来更大的影响。

## 流日志及调用日志 {#outputs.flow_log}

### 过滤器 {#outputs.flow_log.filters}

#### 流日志采集网络类型 {#outputs.flow_log.filters.l4_capture_network_types}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l4_capture_network_types`

Upgrade from old version: `l4_log_tap_types`

**默认值**:
```yaml
outputs:
  flow_log:
    filters:
      l4_capture_network_types:
      - 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| -1 | 关闭 |
| 0 | 所有网络类型 |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

将被存储的流日志采集网络类型列表。

#### 调用日志采集网络类型 {#outputs.flow_log.filters.l7_capture_network_types}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l7_capture_network_types`

Upgrade from old version: `l7_log_store_tap_types`

**默认值**:
```yaml
outputs:
  flow_log:
    filters:
      l7_capture_network_types:
      - 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| -1 | 关闭 |
| 0 | 所有网络类型 |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

将被存储的调用日志采集网络类型列表。

#### 流日志忽略的观测点 {#outputs.flow_log.filters.l4_ignored_observation_points}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l4_ignored_observation_points`

Upgrade from old version: `l4_log_ignore_tap_sides`

**默认值**:
```yaml
outputs:
  flow_log:
    filters:
      l4_ignored_observation_points: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | rest，其他网卡 |
| 1 | c，客户端网卡 |
| 2 | s，服务端网卡 |
| 4 | local，本机网卡 |
| 9 | c-nd，客户端容器节点 |
| 10 | s-nd，服务端容器节点 |
| 17 | c-hv，客户端宿主机 |
| 18 | s-hv，服务端宿主机 |
| 25 | c-gw-hv, 客户端到网关宿主机 |
| 26 | s-gw-hv, 网关宿主机到服务端 |
| 33 | c-gw，客户端到网关 |
| 34 | s-gw, 网关到服务端 |
| 41 | c-p，客户端进程 |
| 42 | s-p, 服务端进程 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

配置该参数后，deepflow-agent将不采集列表中观测点的流日志（同时 TCP 时序数据、Pcap 数据
的采集也将被忽略）。默认值`[]`表示所有观测点均采集。

#### 调用日志忽略的观测点 {#outputs.flow_log.filters.l7_ignored_observation_points}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l7_ignored_observation_points`

Upgrade from old version: `l7_log_ignore_tap_sides`

**默认值**:
```yaml
outputs:
  flow_log:
    filters:
      l7_ignored_observation_points: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | rest，其他网卡 |
| 1 | c，客户端网卡 |
| 2 | s，服务端网卡 |
| 4 | local，本机网卡 |
| 9 | c-nd，客户端容器节点 |
| 10 | s-nd，服务端容器节点 |
| 17 | c-hv，客户端宿主机 |
| 18 | s-hv，服务端宿主机 |
| 25 | c-gw-hv, 客户端到网关宿主机 |
| 26 | s-gw-hv, 网关宿主机到服务端 |
| 33 | c-gw，客户端到网关 |
| 34 | s-gw, 网关到服务端 |
| 41 | c-p，客户端进程 |
| 42 | s-p, 服务端进程 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

配置该参数后，deepflow-agent将不采集列表中观测点的应用调用日志。默认值`[]`表示所有观测点均采集。

### 聚合器 {#outputs.flow_log.aggregators}

#### 聚合健康检查流日志 {#outputs.flow_log.aggregators.aggregate_health_check_l4_flow_log}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_log.aggregators.aggregate_health_check_l4_flow_log`

**默认值**:
```yaml
outputs:
  flow_log:
    aggregators:
      aggregate_health_check_l4_flow_log: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

Agent 会将如下类型的流标记为 `close_type = 正常结束-客户端重置`：
- 客户端发送 SYN，服务端回复 SYN-ACK，客户端发送 RST
- 客户端发送 SYN，服务端回复 SYN-ACK，客户端发送 ACK，客户端发送 RST

此类流量是正常的负载均衡器后端主机检查检查流量，不会携带任何有意义的应用层载荷。

本配置项设置为 `true` 时，Agent 会将流日志的客户端端口号重置为 0 之后再聚合输出，
从而降低带宽和存储开销。

### 限速器 {#outputs.flow_log.throttles}

#### 流日志限速器 {#outputs.flow_log.throttles.l4_throttle}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_log.throttles.l4_throttle`

Upgrade from old version: `l4_log_collect_nps_threshold`

**默认值**:
```yaml
outputs:
  flow_log:
    throttles:
      l4_throttle: 10000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Per Second |
| Range | [100, 1000000] |

**详细描述**:

deepflow-agent 每秒发送的 l4_flow_log 数量上限，实际产生的日志数量超过阈值时，将
使用水库采样限制实际发送数量不超过阈值。

#### 调用日志限速器 {#outputs.flow_log.throttles.l7_throttle}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_log.throttles.l7_throttle`

Upgrade from old version: `l7_log_collect_nps_threshold`

**默认值**:
```yaml
outputs:
  flow_log:
    throttles:
      l7_throttle: 10000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Per Second |
| Range | [100, 1000000] |

**详细描述**:

deepflow-agent 每秒发送的 l7_flow_log 数量上限，实际发送数量超出参数值后，将开启采样。

### 调优 {#outputs.flow_log.tunning}

#### Collector 队列大小 {#outputs.flow_log.tunning.collector_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.flow_log.tunning.collector_queue_size`

Upgrade from old version: `static_config.flow-sender-queue-size`

**默认值**:
```yaml
outputs:
  flow_log:
    tunning:
      collector_queue_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

设置如下队列的长度:
- 3-flow-to-collector-sender
- 3-protolog-to-collector-sender

## Flow 性能指标 {#outputs.flow_metrics}

### Enabled {#outputs.flow_metrics.enabled}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.enabled`

Upgrade from old version: `collector_enabled`

**默认值**:
```yaml
outputs:
  flow_metrics:
    enabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

指标数据采集总开关。关闭后 deepflow-agent 将停止所有应用调用指标、网络指标、应用
调用日志、流日志、TCP 包时序数据、Pcap 数据的采集。

### 过滤器 {#outputs.flow_metrics.filters}

#### 不活跃服务端端口号聚合 {#outputs.flow_metrics.filters.inactive_server_port_aggregation}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.inactive_server_port_aggregation`

Upgrade from old version: `inactive_server_port_enabled`

**默认值**:
```yaml
outputs:
  flow_metrics:
    filters:
      inactive_server_port_aggregation: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启功能后 deepflow-agent 将对非活跃的端口（仅接收数据，不发送数据）的指标数据采集
做聚合处理，所有非活跃端口的数据聚合生成一条'server_port = 0'的指标，而不再生成每个
server_port 单独的指标。

#### 不活跃 IP 地址聚合 {#outputs.flow_metrics.filters.inactive_ip_aggregation}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.inactive_ip_aggregation`

Upgrade from old version: `inactive_ip_enabled`

**默认值**:
```yaml
outputs:
  flow_metrics:
    filters:
      inactive_ip_aggregation: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启功能后 deepflow-agent 将对非活跃 IP（仅接收数据，不发送数据）的指标数据采集做聚合
处理，所有非活跃 IP 的数据聚合生成一条'ip = 0'的指标，而不再生成每个 IP 单独的指标。

#### NPM 指标 {#outputs.flow_metrics.filters.npm_metrics}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.npm_metrics`

Upgrade from old version: `l4_performance_enabled`

**默认值**:
```yaml
outputs:
  flow_metrics:
    filters:
      npm_metrics: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

网络指标的采集开关。关闭后 deepflow-agent 停止采集除基本的吞吐类指标外的其他网络指标。

#### NPM 活跃连接指标 {#outputs.flow_metrics.filters.npm_metrics_concurrent}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.npm_metrics_concurrent`

**默认值**:
```yaml
outputs:
  flow_metrics:
    filters:
      npm_metrics_concurrent: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当关闭时，deepflow-agent 不计算活跃连接指标。

#### APM 指标 {#outputs.flow_metrics.filters.apm_metrics}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.apm_metrics`

Upgrade from old version: `l7_metrics_enabled`

**默认值**:
```yaml
outputs:
  flow_metrics:
    filters:
      apm_metrics: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

应用调用指标的采集开关。关闭后 deepflow-agent 停止采集全部应用调用指标。

#### 秒粒度指标 {#outputs.flow_metrics.filters.second_metrics}

**标签**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.second_metrics`

Upgrade from old version: `vtap_flow_1s_enabled`

**默认值**:
```yaml
outputs:
  flow_metrics:
    filters:
      second_metrics: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

秒级指标的采集开关。关闭后 deepflow-agent 将停止采集秒粒度的网络指标和应用调用指标。

### 调优 {#outputs.flow_metrics.tunning}

#### Sender 队列大小 {#outputs.flow_metrics.tunning.sender_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.flow_metrics.tunning.sender_queue_size`

Upgrade from old version: `static_config.collector-sender-queue-size`

**默认值**:
```yaml
outputs:
  flow_metrics:
    tunning:
      sender_queue_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

配置如下队列的大小:
- 3-doc-to-collector-sender

## NPB (Network Packet Broker) {#outputs.npb}

### 最大 MTU {#outputs.npb.max_mtu}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.max_mtu`

Upgrade from old version: `mtu`

**默认值**:
```yaml
outputs:
  npb:
    max_mtu: 1500
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [500, 10000] |

**详细描述**:

NPB 分发时的 UDP 传输的 MTU 值。注意：当 UDP 报文长度接近 1500 字节后，云平台可能会
修改数据包的尾部数据，因此建议`max_mtu`的值小于 1500。

### RAW_UDP 的 VLAN 标签 {#outputs.npb.raw_udp_vlan_tag}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.raw_udp_vlan_tag`

Upgrade from old version: `output_vlan`

**默认值**:
```yaml
outputs:
  npb:
    raw_udp_vlan_tag: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 4095] |

**详细描述**:

当使用 RAW_UDP Socket 发送 NPB 数据时，通过该参数设置数据包 VLAN 标签。默认值为`0`，表示
不使用 VLAN 标签。

### 额外的 VLAN 头 {#outputs.npb.extra_vlan_header}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.extra_vlan_header`

Upgrade from old version: `npb_vlan_mode`

**默认值**:
```yaml
outputs:
  npb:
    extra_vlan_header: 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | 无 |
| 1 | 802.1Q |
| 2 | QinQ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

设置 NPB 分发数据的 VLAN 模式。`无`表示不加 VLAN；`802.1Q`表示添加 802.1Q header；
`QinQ`表示添加 QinQ。

### 流量全局去重 {#outputs.npb.traffic_global_dedup}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.traffic_global_dedup`

Upgrade from old version: `npb_dedup_enabled`

**默认值**:
```yaml
outputs:
  npb:
    traffic_global_dedup: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

NPB 数据去重开关。开启开关后，将对 NPB 分发做全局去重，避免一份流量在客户端、服务端分发两次。

### 目的端口号 {#outputs.npb.target_port}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.target_port`

Upgrade from old version: `static_config.npb-port`

**默认值**:
```yaml
outputs:
  npb:
    target_port: 4789
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**详细描述**:

NPB 分发使用的目标端口号。

### 自定义 VXLAN Flags {#outputs.npb.custom_vxlan_flags}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.custom_vxlan_flags`

Upgrade from old version: `static_config.vxlan-flags`

**默认值**:
```yaml
outputs:
  npb:
    custom_vxlan_flags: 255
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 255] |

**详细描述**:

使用 VXLAN 分发时设置 VXLAN 内的 Flags 为该值。采集器不会采集分发流量。

这个配置默认会或上0b1000_0000，所以不能配置为 0b1000_0000。

### Overlay VLAN 头剥离 {#outputs.npb.overlay_vlan_header_trimming}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.overlay_vlan_header_trimming`

Upgrade from old version: `static_config.ignore-overlay-vlan`

**默认值**:
```yaml
outputs:
  npb:
    overlay_vlan_header_trimming: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启开关后，deepflow-agent 在 NPB 分发时会剥离 overlay 原始数据包中的 VLAN 头。

### 最大 Tx 吞吐量 {#outputs.npb.max_tx_throughput}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.max_tx_throughput`

Upgrade from old version: `max_npb_bps`

**默认值**:
```yaml
outputs:
  npb:
    max_tx_throughput: 1000
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Mbps |
| Range | [1, 100000] |

**详细描述**:

设置 deepflow-agent 做 NPB 分发的最大吞吐率。

## 压缩 {#outputs.compression}

### Application_Log {#outputs.compression.application_log}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.application_log`

**默认值**:
```yaml
outputs:
  compression:
    application_log: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后，deepflow-agent 将对集成的应用日志数据进行压缩处理，压缩比例在 5:1~20:1 之间。注意：
开启此特性将增加 deepflow-agent 的 CPU 消耗。

### Pcap {#outputs.compression.pcap}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.pcap`

**默认值**:
```yaml
outputs:
  compression:
    pcap: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后，deepflow-agent 将对抓取的 Pcap 数据进行压缩处理，压缩比例在 5:1~10:1 之间。注意：
开启此特性将增加 deepflow-agent 的 CPU 消耗。

### 调用日志 {#outputs.compression.l7_flow_log}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.l7_flow_log`

**默认值**:
```yaml
outputs:
  compression:
    l7_flow_log: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后，deepflow-agent 将对调用日志进行压缩处理，压缩比例在 8:1 左右。注意：
开启此特性将增加 deepflow-agent 的 CPU 消耗。

### 流日志 {#outputs.compression.l4_flow_log}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.l4_flow_log`

**默认值**:
```yaml
outputs:
  compression:
    l4_flow_log: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后，deepflow-agent 将对网络流日志进行压缩处理。注意：
开启此特性将增加 deepflow-agent 的 CPU 消耗。

# 插件 {#plugins}

插件支持
同时匹配插件和自定义提取策略时，优先级为：
1. 插件提取
2. 自定义字段提取
3. 采集器默认提取

## Wasm 插件列表 {#plugins.wasm_plugins}

**标签**:

`hot_update`

**FQCN**:

`plugins.wasm_plugins`

Upgrade from old version: `wasm_plugins`

**默认值**:
```yaml
plugins:
  wasm_plugins: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

需要加载的 Wasm 插件列表。

## SO 插件列表 {#plugins.so_plugins}

**标签**:

`hot_update`

**FQCN**:

`plugins.so_plugins`

Upgrade from old version: `so_plugins`

**默认值**:
```yaml
plugins:
  so_plugins: []
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

需要加载的 so 插件列表。

# 开发 {#dev}

## Feature Flags {#dev.feature_flags}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`dev.feature_flags`

Upgrade from old version: `static_config.feature-flags`

**默认值**:
```yaml
dev:
  feature_flags: []
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

未发布的采集器特性可以通过该选项开启。
