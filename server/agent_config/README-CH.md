# 全局配置 {#global}

## Enabled {#global.enabled}

**标签**:

`hot_update`

**FQCN**:

`global.enabled`

Upgrade from old version: `enabled`

**默认值**:
```yaml
global:
  enabled: true
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

禁用 / 启用 deepflow-agent。

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

### CPU 限制 (Cores) {#global.limits.max_cpus}

**标签**:

<mark></mark>
<mark>deprecated</mark>

**FQCN**:

`global.limits.max_cpus`

Upgrade from old version: `max_cpus`

**默认值**:
```yaml
global:
  limits:
    max_cpus: 1
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

### 内存限制 {#global.limits.max_memory}

**标签**:

`hot_update`

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

deepflow-agent 使用 cgroups 限制自身的 memory 用量.

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
    max_log_backhaul_rate: 300
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Lines/Hour |
| Range | [0, 10000] |

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

用于控制 deepflow-agent 创建的进程数量。

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

When the host has an invalid NFS file system or a docker is running,
sometime program hang when checking the core file, so the core file
check provides a switch to prevent the process hang. Additional links:
- https://serverfault.com/questions/367438/ls-hangs-for-a-certain-directory
- https://unix.stackexchange.com/questions/495854/processes-hanging-when-trying-to-access-a-file

## 熔断机制 {#global.circuit_breakers}

控制 deepflow-agent 在一定的环境条件下停止运行或停止部分功能。

### 系统空闲内存百分比 {#global.circuit_breakers.sys_free_memory_percentage}

计算公式：`(free_memory / total_memory) * 100%`

#### 触发阈值 {#global.circuit_breakers.sys_free_memory_percentage.trigger_threshold}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.sys_free_memory_percentage.trigger_threshold`

Upgrade from old version: `sys_free_memory_limit`

**默认值**:
```yaml
global:
  circuit_breakers:
    sys_free_memory_percentage:
      trigger_threshold: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | % |
| Range | [0, 100] |

**详细描述**:

当系统空闲内存低于此阈值的 90% 时，deepflow-agent 将自动重启。

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

当`相对系统负载`高于此阈值时，deepflow-agent 自动停止运行；取值为 0 时，该特性不生效。

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

当`相对系统负载`连续 5 分钟低于此阈值时，deepflow-agent 自动从
停止状态恢复运行。取值为 0 时，该特性不生效。

#### 观测指标 {#global.circuit_breakers.relative_sys_load.system_load_circuit_breaker_metric}

**标签**:

`hot_update`

**FQCN**:

`global.circuit_breakers.relative_sys_load.system_load_circuit_breaker_metric`

Upgrade from old version: `system_load_circuit_breaker_metric`

**默认值**:
```yaml
global:
  circuit_breakers:
    relative_sys_load:
      system_load_circuit_breaker_metric: load15
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

如果流量分发所用网络接口的出方向吞吐量达到或超出此阈值，deepflow-agent 停止流量
分发；如果该网络接口的出方向吞吐量连续 5 个监控周期低于`(trigger_threshold -
outputs.npb.max_npb_throughput)*90%`，deepflow-agent 恢复流量分发。

注意：
1. 取值为 0 时，该特性不生效；
2. 若取非 0 值，必须大于 `max_npb_throughput`。

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

操作系统尽可能使用指定 ID 的 CPU 核运行 deepflow-agent 进程。举例：
```yaml
global:
  tunning:
    cpu_affinity: [1, 3, 5, 7, 9]
```

### 进程调度优先级 {#global.tunning.process_scheduling_priority}

**标签**:

<mark>agent_restart</mark>

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

<mark>agent_restart</mark>

**FQCN**:

`global.tunning.idle_memory_trimming`

Upgrade from old version: `static_config.memory-trim-disabled`

**默认值**:
```yaml
global:
  tunning:
    idle_memory_trimming: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启闲置内存修剪特性，将降低 agent 内存使用量，但可能会损失 agent 处理性能。

### 资源监控间隔 {#global.tunning.resource_monitoring_interval}

**标签**:

<mark>agent_restart</mark>

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
| Range | [0, '365d'] |

**详细描述**:

当 deepflow-agent 与 deepflow-server 之间的时间偏移大于‘max_drift’设置值时，agent 会自动重启。

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
| Range | [0, '365d'] |

**详细描述**:

当 deepflow-agent 与 deepflow-server 之间的时间偏移大于‘min_drift’设置值时，对 agent 的
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

### Controller IP 地址 {#global.communication.controller_ip}

**标签**:

`hot_update`

**FQCN**:

`global.communication.controller_ip`

Upgrade from old version: `proxy_controller_ip`

**默认值**:
```yaml
global:
  communication:
    controller_ip: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | ip |

**详细描述**:

用于设置 deepflow-server 向 deepflow-agent 下发的 server 端控制面通信 IP；如果不设置本
参数，server 下发自己的节点 IP 作为 server 端控制面通信IP。该参数通常用于 server 端使用负载
均衡或虚 IP 对外提供服务的场景。

### Controller 端口号 {#global.communication.controller_port}

**标签**:

`hot_update`

**FQCN**:

`global.communication.controller_port`

Upgrade from old version: `proxy_controller_port`

**默认值**:
```yaml
global:
  communication:
    controller_port: 30035
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

<mark>agent_restart</mark>

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

TODO

## 自监控 {#global.self_monitoring}

配置 deepflow-agent 自身诊断相关的参数

### 日志 {#global.self_monitoring.log}

deepflow-agent 运行日志相关参数

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
| WARNING | |
| ERROR | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

deepflow-agent 运行日志输出等级。

#### 日志文件 {#global.self_monitoring.log.log_file}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.self_monitoring.log.log_file`

Upgrade from old version: `static_config.log-file`

**默认值**:
```yaml
global:
  self_monitoring:
    log:
      log_file: /var/log/deepflow_agent/deepflow_agent.log
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
trident 用于诊断的 UDP 监听端口，默认值为 0 ，表示使用随机的端口。

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

### Hostname {#global.self_monitoring.hostname}

**标签**:

`hot_update`

**FQCN**:

`global.self_monitoring.hostname`

Upgrade from old version: `host`

**默认值**:
```yaml
global:
  self_monitoring:
    hostname: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

覆盖 statsd 主机标签。

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
    data_file_dir: /var/log/deepflow_agent/
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

数据文件的写入位置。

## 标签 {#global.tags}

deepflow-agent 关联标签。

### Region ID {#global.tags.region_id}

**标签**:

`hot_update`

**FQCN**:

`global.tags.region_id`

Upgrade from old version: `region_id`

**默认值**:
```yaml
global:
  tags:
    region_id: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

采集器所在区域 ID 或数据节点所在区域 ID。

### 容器集群 ID {#global.tags.pod_cluster_id}

**标签**:

`hot_update`

**FQCN**:

`global.tags.pod_cluster_id`

Upgrade from old version: `pod_cluster_id`

**默认值**:
```yaml
global:
  tags:
    pod_cluster_id: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

采集器所在容器集群 ID。

### VPC ID {#global.tags.vpc_id}

**标签**:

`hot_update`

**FQCN**:

`global.tags.vpc_id`

Upgrade from old version: `epc_id`

**默认值**:
```yaml
global:
  tags:
    vpc_id: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

采集器所在的 vpc 的 ID, 仅对 Workload-V/P, 容器-V/P 类型有意义。

### Agent ID {#global.tags.agent_id}

**标签**:

`hot_update`

**FQCN**:

`global.tags.agent_id`

Upgrade from old version: `vtap_id`

**默认值**:
```yaml
global:
  tags:
    agent_id: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 64000] |

**详细描述**:

采集器 ID。

### 采集器类型 {#global.tags.agent_type}

**标签**:

`hot_update`

**FQCN**:

`global.tags.agent_type`

Upgrade from old version: `trident_type`

**默认值**:
```yaml
global:
  tags:
    agent_type: 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | TT_UNKNOWN |
| 1 | TT_PROCESS, Agent in KVM |
| 2 | TT_VM, Agent in a dedicated VM on ESXi |
| 3 | TT_PUBLIC_CLOUD, Agent in Cloud host (VM) |
| 5 | TT_PHYSICAL_MACHINE, Agent in Cloud host (BM), or legacy host |
| 6 | TT_DEDICATED_PHYSICAL_MACHINE, Agent in a dedicated host to receive mirror traffic |
| 7 | TT_HOST_POD, Agent in K8s Node (Cloud BM, or legacy host) |
| 8 | TT_VM_POD, Agent in K8s Node (Cloud VM) |
| 9 | TT_TUNNEL_DECAPSULATION, Agent in a dedicated host to decap tunnel traffic |
| 10 | TT_HYPER_V_COMPUTE, Agent in Hyper-V Compute Node |
| 11 | TT_HYPER_V_NETWORK, Agent in Hyper-V Network Node |
| 12 | TT_K8S_SIDECAR, Agent in K8s POD |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 12] |

**详细描述**:

采集器类型。

### 团队 ID {#global.tags.team_id}

**标签**:

`hot_update`

**FQCN**:

`global.tags.team_id`

Upgrade from old version: `team_id`

**默认值**:
```yaml
global:
  tags:
    team_id: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

采集器所在的团队的 ID。

### 组织 ID {#global.tags.organize_id}

**标签**:

`hot_update`

**FQCN**:

`global.tags.organize_id`

Upgrade from old version: `organize_id`

**默认值**:
```yaml
global:
  tags:
    organize_id: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

采集器所在的组织的 ID。

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
    enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

开启后 deepflow-agent 将获取操作系统的进程信息，并上报至 deepflow-server。该参数仅对
CHOST_VM, CHOST_BM, K8S_VM, K8S_BM 等运行环境的 agent 有效。

### /proc 目录 {#inputs.proc.proc_dir_path}

**标签**:

<mark>agent_restart</mark>

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

### 同步间隔 {#inputs.proc.sync_interval}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.sync_interval`

Upgrade from old version: `static_config.os-proc-socket-sync-interval`

**默认值**:
```yaml
inputs:
  proc:
    sync_interval: 10s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1h'] |

**详细描述**:

进程和 Socket 信息同步的时间周期。

### 最小活跃时间 {#inputs.proc.min_lifetime}

**标签**:

<mark>agent_restart</mark>

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

如果进程的活跃时间低于该参数值，deepflow-agent 将不上报该进程的信息。

### Tag 提取 {#inputs.proc.tag_extraction}

#### 脚本命令 {#inputs.proc.tag_extraction.script_command}

**标签**:

<mark>agent_restart</mark>

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

<mark>agent_restart</mark>

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

deepflow-agent 执行 `os-app-tag-exec` 脚本命令的用户名。

### 进程匹配器 {#inputs.proc.process_matcher}

**标签**:

<mark>agent_restart</mark>

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
      - ebpf.profile.off_cpu
      match_regex: deepflow-*
      only_in_container: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

Will traverse over the entire array, so the previous ones will be matched first.
when match_type is parent_process_name, will recursive to match parent proc name,
and rewrite_name field will ignore. rewrite_name can replace by regexp capture group
and windows style environment variable, for example: `$1-py-script-%HOSTNAME%` will
replace regexp capture group 1 and HOSTNAME env var. If proc not match any regexp
will be accepted (essentially will auto append `- match_regex: .*` at the end).

Configuration Item:
- match_regex: The regexp use for match the process, default value is `.*`
- match_type: regexp match field, default value is `process_name`, options are
  [process_name, cmdline, cmdline_with_args, parent_process_name, tag]
- ignore: Whether to ignore when regex match, default value is `false`
- rewrite_name: The name will replace the process name or cmd use regexp replace.
  Default value `""` means no replacement.

Example:
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
    - match_regex: .+ # match after concatenating a tag key and value pair using colon,
                      # i.e., an regex `app:.+` can match all processes has a `app` tag
      match_type: tag
```

#### 匹配正则表达式 {#inputs.proc.process_matcher.match_regex}

**标签**:

<mark>agent_restart</mark>

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

The regex of matcher.

#### 匹配类型 {#inputs.proc.process_matcher.match_type}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.process_matcher.match_type`

Upgrade from old version: `static_config.os-proc-regex.match-regex`

**默认值**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_type: ''
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| process_name | |
| cmdline | |
| parent_process_name | |
| tag | |
| cmdline_with_args | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

The type of matcher.

#### 匹配语言 {#inputs.proc.process_matcher.match_languages}

**标签**:

<mark>agent_restart</mark>

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
| nodejs | |
| dotnet | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

Default value `[]` match all languages.

#### 匹配用户名 {#inputs.proc.process_matcher.match_usernames}

**标签**:

<mark>agent_restart</mark>

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

Default value `[]` match all usernames.

#### 仅匹配容器内的进程 {#inputs.proc.process_matcher.only_in_container}

**标签**:

<mark>agent_restart</mark>

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

Default value true means only match processes in container.

#### 仅匹配有 Tag 的进程 {#inputs.proc.process_matcher.only_with_tag}

**标签**:

<mark>agent_restart</mark>

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

Default value false means match processes with or without tags.

#### 忽略 {#inputs.proc.process_matcher.ignore}

**标签**:

<mark>agent_restart</mark>

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

Whether to ingore matched processes..

#### 重命名 {#inputs.proc.process_matcher.rewrite_name}

**标签**:

<mark>agent_restart</mark>

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

New name after matched.

#### 开启功能列表 {#inputs.proc.process_matcher.enabled_features}

**标签**:

<mark>agent_restart</mark>

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
| proc.socket_list | |
| proc.symbol_table | |
| proc.proc_event | |
| ebpf.socket.uprobe.golang | |
| ebpf.socket.uprobe.tls | |
| ebpf.socket.uprobe.rdma | |
| ebpf.file.io_event | |
| ebpf.file.management_event | |
| ebpf.profile.on_cpu | |
| ebpf.profile.off_cpu | |
| ebpf.profile.memory | |
| ebpf.profile.cuda | |
| ebpf.profile.hbm | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

Enabled feature list.

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
| Type | string |

**详细描述**:

如果 Golang（版本 >= 1.13 and < 1.18条件下）进程运行时裁切了标准符号
表，开启此开关后 deepflow-agent 将解析生成 Golang-specific 符号表以
完善 eBPF uprobe 数据，实现 Golang 程序的零侵扰调用链追踪。注意：开启
该开关后，eBPF 程序初始化过程可能会持续 10 分钟以上的时间。
配置方法：
- 在'golang'的参数中配置进程的正则表达式，比如：`golang: .*`
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
  - 检查目录下是否有符号表，如果结果中出现 "no symbols"，则说明符号表缺失，需要开启 Golang 程序符号表解析开关.
    ```
    # nm /proc/1946/root/usr/local/bin/kube-controller-manager
    nm: /proc/1946/root/usr/local/bin/kube-controller-manager: no symbols
    ```
- deepflow-agent 启动阶段运行日志中出现类似下面的信息，说明 Golang 进程已经被成功 hook。
  ```
  [eBPF] INFO Uprobe [/proc/1946/root/usr/local/bin/kube-controller-manager] pid:1946 go1.16.0
  entry:0x25fca0 size:1952 symname:crypto/tls.(*Conn).Write probe_func:uprobe_go_tls_write_enter rets_count:0
  ```

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

当 deepflow-agent 在 Java 进程的函数调用栈中发现未能解析的函数名时，将触发进程函数符号表的再生成
过程，而由于 Java 使用了 JIT 编译机制，符号表的再生成过程将延迟一定的时间。

TODO

##### 符号表文件最大大小 {#inputs.proc.symbol_table.java.max_symbol_file_size}

**标签**:

<mark>agent_restart</mark>

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

Packets of interfaces in the same group can be aggregated together,
Only effective when capture_mode is 0.

Example:
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

TODO

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
在匹配命中的网络 namespace 中根据`tap_interface_regex`正则匹配网络接口并采集流量。默认
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

如果不配置该参数，则采集全部流量。BPF 语法详见：https://biot.com/capstats/bpf.html

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
| Range | [0, 8] |

**详细描述**:

TODO

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

`本地流量`和`虚拟网络镜像`模式下，需开启此开关，并配置 `afpacket-blocks` 参数。

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

数据包 Fanout 的路数大于 1 时，deepflow-agent 将开启多个 dispatcher 线程，并把数据包分散到多个处理
线程并行处理，以优化应用的的性能和弹性。增加`packet_fanout_count`可以降低多核服务器的操作系统软中断数
量，但会消耗更多的 CPU 和内存。

注意：参数仅在`capture_mode`为 0，且`extra_netns_regex`为空时有效。

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
- https://github.com/torvalds/linux/blob/afcd48134c58d6af45fb3fdb648f1260b20f2326/include/uapi/linux/if_packet.h#L71
- https://www.stackpath.com/blog/bpf-hook-points-part-1/

### 特殊网络 {#inputs.cbpf.special_network}

#### DPDK {#inputs.cbpf.special_network.dpdk}

##### Enabled {#inputs.cbpf.special_network.dpdk.enabled}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.dpdk.enabled`

Upgrade from old version: `static_config.dpdk-enabled`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      dpdk:
        enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

TODO

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
| Type | bool |

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

TODO

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

TODO

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

TODO

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
      max_capture_pps: 200
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Kpps |
| Range | [1, 1000000] |

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

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

deepflow-agent 需要对数据包解封装的隧道协议。

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

流量镜像模式下，deepflow-agent 需要剥离的隧道头协议类型。

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

在`物理网络镜像`模式下，deepflow-agent 通过镜像流量的外层 VLAN 标签识别并标记采集数据的
TAP(Traffic Access Point)值。当流量外层 VLAN 标签没有对应的 TAP 值，或 VLAN pcp 值与
'vlan_pap_in_physical_mirror_traffic'的配置不一致时，deepflow-agent 使用本参数值
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

`物理网络镜像`模式下该参数配置为 `true` 时，deepflow-agent 将不对数据包做去重处理。

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

`物理网络镜像`模式下该参数配置为 `true` 时，deepflow-agent 会将流量识别为 NFVGW 流量。

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

Upgrade from old version: `static_config.ebpf.uprobe-process-name-regexs.golang`

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
| Type | string |

**详细描述**:

Golang 程序 HTTP2/HTTPS 协议数据采集及零侵扰追踪特性的开启开关。

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
| Range | [0, '1d'] |

**详细描述**:

Golang 程序追踪时请求与响应之间的最大时间间隔，设置为 0 时，Golang 程序的零侵扰追踪特性自动关闭。

##### TLS {#inputs.ebpf.socket.uprobe.tls}

###### Enabled {#inputs.ebpf.socket.uprobe.tls.enabled}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.tls.enabled`

Upgrade from old version: `static_config.ebpf.uprobe-process-name-regexs.openssl`

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
| Type | string |

**详细描述**:

应用程序 openssl 采集开关，开启后 deepflow-agent 将获取进程信息并用 Uprobe  Hook 到 opessl 的
加密/解密接口，以采集 HTTPS 协议加密前、解密后的数据。
确定应用程序是否使用 openssl 的方法：
```
`cat /proc/<PID>/maps | grep "libssl.so"`
```

#### Kprobe {#inputs.ebpf.socket.kprobe}

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

###### 白名单 {#inputs.ebpf.socket.kprobe.whitelist.port}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.whitelist.port`

Upgrade from old version: `static_config.ebpf.kprobe-whitelist.port-list`

**默认值**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        whitelist:
          port: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

TCP 和 UDP 的端口白名单列表，白名单生效优先级低于 kprobe 黑名单。

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

当完整的map预分配过于昂贵时，将 `map_prealloc_disabled` 设置为 true 可以防止在定义map时进行
内存预分配，但这可能会导致一些性能下降。此配置仅适用于 `BPF_MAP_TYPE_HASH` 类型的 ebpf map。
目前适用于 socket trace 和 uprobe Golang/OpenSSL trace 功能。禁用内存预分配大约会减少45M的内存占用。

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
条事件数据占用的字节数上限受`l7_log_packet_size`控制）。在 Syscall 数据乱序较严重导致应用调用采集不全的环境
中，可适当调大该参数。

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
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置后 deepflow-agent 将对指定应用协议的处理增加乱序重排过程。注意：（1）开启特性将消耗更多的内存，因此
需关注 agent 内存用量；（2）如需对`gRPC`协议乱序重排，请配置`HTTP2`协议。

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
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置后 deepflow-agent 将对指定应用协议的处理增加分片重组过程，将多个 Syscall 的内容分片重组后再进行
协议解析，以增强应用协议的采集成功率。注意：（1）该特性的生效的前提条件是`syscall-out-of-order-reassembly`
开启并生效；（2）如需对`gRPC`协议乱序重排，请配置`HTTP2`协议。

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
- 0：不采集任何文件 IO 事件。
- 1：仅采集调用生命周期内的文件 IO 事件。
- 2：采集所有的文件 IO 事件。

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

### Profile {#inputs.ebpf.profile}

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
- 1: 表示在采集 On-CPU 采样数据时获取 CPUID （On-CPU 剖析时，支持对单个 CPU 的分析）。
- 0: 表示在采集 On-CPU 采样数据时不获取 CPUID （On-CPU 剖析时，不支持单个 CPU 的分析）。

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
- 1: 表示在采集 Off-CPU 数据时获取 CPUID （Off-CPU 剖析时，支持对单个 CPU 的分析）。
- 0: 表示在采集 Off-CPU 数据时不获取 CPUID （Off-CPU 剖析时，不支持单个 CPU 的分析）。

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
| Range | [0, '1h'] |

**详细描述**:

低于'最小阻塞时间'的 Off-CPU 数据将被 deepflow-agent 忽略，'最小阻塞时间'设置为 '0' 表示
采集所有的 Off-CPU 数据。由于 CPU 调度事件数量庞大（每秒可能超过一百万次），调小该参数将带来
明显的资源开销，如果需要跟踪大时延的调度阻塞事件，建议调大该参数，以降低资源开销。另外，deepflow-agent
不采集阻塞超过 1 小时的事件。

#### Memory {#inputs.ebpf.profile.memory}

##### Disabled {#inputs.ebpf.profile.memory.disabled}

**标签**:

<mark>agent_restart</mark>
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

#### 预处理 {#inputs.ebpf.profile.preprocess}

##### 函数栈压缩 {#inputs.ebpf.profile.preprocess.stack_compression}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.preprocess.stack_compression`

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

TODO

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

TODO

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

TODO

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
| Range | [100000, 2000000] |

**详细描述**:

TODO

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
| Range | [100000, 2000000] |

**详细描述**:

TODO

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
| Range | [100000, 2000000] |

**详细描述**:

TODO

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

开启开关后，deepflow-agent 将采集宿主机中的 VM 信息和网络信息，并上报/同步至 deepflow-server。

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
- 0: 从 tap 接口的 MAC 地址中提取 VM 的 MAC 地址
- 1: 从 tap 接口的名字中提取 MAC 地址
- 2: 从 VM XML 文件中提取 MAC 地址

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

TODO

### 采集 K8s 资源 {#inputs.resources.kubernetes}

#### Enabled {#inputs.resources.kubernetes.enabled}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.kubernetes.enabled`

Upgrade from old version: `kubernetes_api_enabled`

**默认值**:
```yaml
inputs:
  resources:
    kubernetes:
      enabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

当同个 K8s 集群中有多个 deepflow-agent 时，只有一个 deepflow-agent 会被启用采集 K8s 资源。

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

TODO

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
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**详细描述**:

Specify kubernetes resources to watch.

To disable a resource, add an entry to the list with `disabled: true`:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - name: services
        disabled: true
```

To enable a resource, add an entry of this resource to the list. Be advised that
this setting overrides the default of the same resource. For example, to enable
`statefulsets` in both group `apps` (the default) and `apps.kruise.io` will require
two entries:
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

To watching `routes` in openshift you can use the following settings:
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

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

K8s API resource name.

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

K8s API resource group.

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

K8s API version.

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

K8s API resource disabled.

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

K8s API resource field selector.

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

TODO

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

TODO

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
      - 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

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

TODO

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

Upgrade from old version: `static_config.external-agent-http-proxy-compressed`

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

#### Label 键长度限制 {#inputs.integration.prometheus_extra_labels.label_length}

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

deepflow-agent 对 Prometheus 额外 label 解析并采集时，key 字段的长度上限。

#### Label 值长度限制 {#inputs.integration.prometheus_extra_labels.value_length}

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

deepflow-agent 对 Prometheus 额外 label 解析并采集时，value 字段的长度上限。

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

**详细描述**:

设置为`0`时，deepflow-agent 根据 `max_memory` 参数自动调整 Fast-path 字典大小。

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

设置为`true`时，deepflow-agent 不启用 fast path。

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

调大该参数，deepflow-agent 将消耗更多的内存。

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

TODO

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

TODO

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

#### Sender 队列数量 {#processors.packet.tcp_header.sender_queue_count}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.tcp_header.sender_queue_count`

Upgrade from old version: `static_config.packet-sequence-queue-count`

**默认值**:
```yaml
processors:
  packet:
    tcp_header:
      sender_queue_count: 1
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 64] |

**详细描述**:

TCP 包时序数据发送队列的数量。

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

TODO

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

TODO

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

TODO

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

TODO

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

含义待明确。

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
      inference_max_retries: 5
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 10000] |

**详细描述**:

deepflow-agent 会周期性标记每一个 `<vpc, ip, protocol, port>` 四元组承载的应用协议类型，以加速
后续数据的应用协议采集过程。如果一个时间周期内，连续多次尝试解析 Packet 数据、Socket 数据无法推断
出该四元组承载的应用协议，agent 会将该四元组标记为 unknown 类型，并在本周期内暂停对后续数据的应用
协议解析，以避免更多的无效运算。该参数控制每个时间周期内的应用协议解析重试次数。

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
      inference_result_ttl: 60
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | [0, '1d'] |

**详细描述**:

deepflow-agent 会周期性标记每一个<vpc, ip, protocol, port>四元组承载的应用协议类型，以加速
后续数据的应用协议采集过程。为避免误判，应用协议类型的标记结果会周期性更新。该参数控制应用协议的更
新周期。

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
      - Dubbo
      - SofaRPC
      - FastCGI
      - bRPC
      - MySQL
      - PostgreSQL
      - Oracle
      - Redis
      - MongoDB
      - Kafka
      - MQTT
      - AMQP
      - OpenWire
      - NATS
      - Pulsar
      - ZMTP
      - DNS
      - TLS
      - Custom
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
        Kafka: 1-65535
        MQTT: 1-65535
        MongoDB: 1-65535
        MySQL: 1-65535
        NATS: 1-65535
        OpenWire: 1-65535
        Oracle: 1521
        PostgreSQL: 1-65535
        Pulsar: 1-65535
        Redis: 1-65535
        SofaRPC: 1-65535
        TLS: 443,6443
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

配置样例: `80,1000-2000`

注意：
1. 该参数中，HTTP2 和 TLS 协议的配置仅对 Kprobe有效，对 Uprobe 无效；
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
        DNS: []
        Dubbo: []
        FastCGI: []
        HTTP: []
        HTTP2: []
        Kafka: []
        MQTT: []
        MongoDB: []
        MySQL: []
        NATS: []
        OpenWire: []
        Oracle: []
        PostgreSQL: []
        Pulsar: []
        Redis: []
        SOFARPC: []
        TLS: []
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

控制不同应用协议数据采集时的 Tag。

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
          - field-name: request_resource  # endpoint, request_type, request_domain, request_resource
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

Match field name.

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

Match operator.

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

TODO

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
      tcp_request_timeout: 1800s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '3600s'] |

**详细描述**:

deepflow-agent 采集 TCP 承载的应用调用时等待响应消息的最大时长，如果响应与请求之间的时间差超过
该参数值，该次调用将被识别为超时。该参数需大于会话合并的 SLOT_TIME （10s），并小于 3600s。

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

deepflow-agent 采集 UDP 承载的应用调用时等待响应消息的最大时长，如果响应与请求之间的时间差超过
该参数值，该次调用将被识别为超时。该参数需大于会话合并的 SLOT_TIME （10s），并小于 300s。

#### 会话合并窗口时长 {#processors.request_log.timeouts.session_aggregate_window_duration}

**标签**:

<mark>agent_restart</mark>

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
        http_real_client: X_Forwarded_For
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，deepflow-agent 会尝试从 HTTP header 中匹配特征字段，并将匹配到
的结果填充到应用调用日志的`http_proxy_client`字段中，作为调用链追踪的特征值。

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
        x_request_id: X_Request_ID
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置该参数后，deepflow-agent 会尝试从 HTTP header 中匹配特征字段，并将匹配到
的结果填充到应用调用日志的`x_request_id`字段中，作为调用链追踪的特征值。

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

TODO

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

TODO

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

配置 HTTP、HTTP2、gRPC 等协议的额外提取字段。注意：如需配置`gRPC`协议，使用`HTTP2`匹配。

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

TODO

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

TODO

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

应用调用日志采集解析的最大 payload 长度。
注意：eBPF 数据的 payload 可解析长度上限为 16384 Byte。

#### 会话聚合桶容量 {#processors.request_log.tunning.session_aggregate_slot_capacity}

**标签**:

<mark>agent_restart</mark>

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

TODO

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
| Range | ['1s', '10s'] |

**详细描述**:

Extra tolerance for QuadrupleGenerator receiving 1s-FlowLog.

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
| Range | ['1s', '10s'] |

**详细描述**:

TODO

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

TODO

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

TODO

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

TODO

#### 超时设置 {#processors.flow_log.conntrack.timeouts}

##### Established {#processors.flow_log.conntrack.timeouts.established}

**标签**:

<mark>agent_restart</mark>

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

<mark>agent_restart</mark>

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

TODO

##### Opening RST {#processors.flow_log.conntrack.timeouts.opening_rst}

**标签**:

<mark>agent_restart</mark>

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

TODO

##### Others {#processors.flow_log.conntrack.timeouts.others}

**标签**:

<mark>agent_restart</mark>

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

TODO

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

TODO

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

TODO

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

待理解

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

2-second-flow-to-minute-aggrer 的队列大小。

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

TODO

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

TODO

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

### PCAP Socket 类型 {#outputs.socket.pcap_socket_type}

**标签**:

`hot_update`

**FQCN**:

`outputs.socket.pcap_socket_type`

Upgrade from old version: `compressor_socket_type`

**默认值**:
```yaml
outputs:
  socket:
    pcap_socket_type: TCP
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| TCP | |
| UDP | |
| RAW_UDP | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

配置 deepflow-agent 向 deepflow-server 回传 PCAP 数据所用的 Socket 类型。
RAW_UDP 使用 RawSocket 发送 UDP 报文，可以带来更高的性能，但在一些环境中存在兼
容性问题。

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

### Multiple Sockets To Ingester {#outputs.socket.multiple_sockets_to_ingester}

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

TODO

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
      l7_capture_network_types: []
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

TODO

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

deepflow-agent 每秒发送的 l4_flow_log 数量上限，实际发送数量超出参数值后，将开启采样。

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

#### Collector 队列数量 {#outputs.flow_log.tunning.collector_queue_count}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.flow_log.tunning.collector_queue_count`

Upgrade from old version: `static_config.flow-sender-queue-count`

**默认值**:
```yaml
outputs:
  flow_log:
    tunning:
      collector_queue_count: 1
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 64] |

**详细描述**:

设置如下队列的数量：
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
- 2-doc-to-collector-sender

#### Sender 队列数量 {#outputs.flow_metrics.tunning.sender_queue_count}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.flow_metrics.tunning.sender_queue_count`

Upgrade from old version: `static_config.collector-sender-queue-count`

**默认值**:
```yaml
outputs:
  flow_metrics:
    tunning:
      sender_queue_count: 1
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 64] |

**详细描述**:

配置如下队列的数量：TODO

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

设置 NPB 分发数据的 VLAN 模式。`0`表示不加 VLAN；`1`表示添加 802.1Q header；
`2`表示添加 QinQ。

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

TODO

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

# 插件 {#plugins}

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

TODO

