# 全局配置 {#global}

## 资源限制 {#global.limits}

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

deepflow-agent 使用 cgroups 来限制 CPU 自身的 CPU 用量，
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

### 日志回传速率限制 {#global.limits.max_log_backhaul_rate}

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

deepflow-agent 会将自身的日志回传给 deepflow-server，设置为 0 表示
速率不设限制。

### 本地日志文件大小限制 {#global.limits.max_local_log_file_size}

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

The maximum disk space allowed for deepflow-agent log files.

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

The retention time for deepflow-agent log files.

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

Maximum number of threads that deepflow-agent is allowed to launch.

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

Maximum number of processes that deepflow-agent is allowed to launch.

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

### 系统空闲内存百分比 {#global.circuit_breakers.sys_free_memory_percentage}

Calculation Method: `(free_memory / total_memory) * 100%`

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

The limit of the percentage of system free memory.
When the free percentage is lower than 90% of this value,
the agent will automatically restart.

### 相对系统负载 {#global.circuit_breakers.relative_sys_load}

Calculation Method: `system_load / total_cpu_cores`

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

When the load of the Linux system divided by the number of
CPU cores exceeds this value, the agent automatically enters
the disabled state. It will automatically recover if it remains
below 90% of this value for a continuous 5 minutes. Setting it
to 0 disables this feature.

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

When the system load of the Linux system divided by the
number of CPU cores is continuously below this value for 5
minutes, the agent can recover from the circuit breaker
disabled state, and setting it to 0 means turning off the
circuit breaker feature.

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

The system load circuit breaker mechanism uses this metric,
and the agent will check this metric every 10 seconds by default.

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

When the outbound throughput of the NPB interface reaches or exceeds
the threshold, the broker will be stopped, after that the broker will
be resumed if the throughput is lower than
`(trigger_threshold - outputs.npb.max_npb_throughput)*90%`
within 5 consecutive monitoring intervals.

Attention: When configuring this value, it must be greater than
`outputs.npb.max_npb_throughput`. Set to 0 will disable this feature.

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

Monitoring interval for outbound traffic rate of NPB interface.

## 调优 {#global.tunning}

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

CPU affinity is the tendency of a process to run on a given CPU for as long as possible
without being migrated to other processors. Example: `cpu-affinity: [1, 3, 5, 7, 9]`.

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

The smaller the value of process scheduling priority, the higher the priority of the
`deepflow-agent` process, and the larger the value, the lower the priority.

### 闲置内存裁剪 {#global.tunning.idle_memory_trimming}

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

Proactive memory trimming can effectively reduce memory usage, but there may be
performance loss.

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

The agent will monitor:
1. System free memory
2. Get the number of threads of the agent itself by reading the file information
   under the /proc directory
3. Size and number of log files generated by the agent.
4. System load
5. Agent memory usage (check if memory trimming is needed)

## NTP 时钟同步 {#global.ntp}

此同步机制不会改变主机的时钟，仅供 deepflow-agent 进程内部使用。

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

Whether to synchronize the clock to the deepflow-server, this behavior
will not change the time of the deepflow-agent running environment.

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

When the clock drift exceeds this value, the agent will restart.

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

When the clock drift exceeds this value, the timestamp will be corrected.

## 通信 {#global.communication}

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

The interval at which deepflow-agent proactively requests configuration and
tag information from deepflow-server.

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

The maximum time that the agent is allowed to work normally when it
cannot connect to the server. After the timeout, the agent automatically
enters the disabled state.

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

When this value is set, deepflow-agent will use this IP to access the
control plane port of deepflow-server, which is usually used when
deepflow-server uses an external load balancer.

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

The control plane port used by deepflow-agent to access deepflow-server.
The default port within the same K8s cluster is 20035, and the default port
of deepflow-agent outside the cluster is 30035.

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

When this value is set, deepflow-agent will use this IP to access the
data plane port of deepflow-server, which is usually used when
deepflow-server uses an external load balancer.

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

The data plane port used by deepflow-agent to access deepflow-server.
The default port within the same K8s cluster is 20033, and the default port
of deepflow-agent outside the cluster is 30033.

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

gRPC socket buffer size.

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

Used when deepflow-agent uses an external IP address to access
deepflow-server. For example, when deepflow-server is behind a NAT gateway,
or the host where deepflow-server is located has multiple node IP addresses
and different deepflow-agents need to access different node IPs, you can
set an additional NAT IP for each deepflow-server address, and modify this
value to true.

## 自监控 {#global.self_monitoring}

### 日志 {#global.self_monitoring.log}

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

Log level of deepflow-agent.

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

When enabled, deepflow-agent will send its own logs to deepflow-server.

### Profile {#global.self_monitoring.profile}

#### Enabled {#global.self_monitoring.profile.enabled}

**标签**:

<mark>agent_restart</mark>

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

Only available for Trident (Golang version of Agent).

### Debug {#global.self_monitoring.debug}

#### 监听 UDP 端口号 {#global.self_monitoring.debug.listen_udp_port}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.self_monitoring.debug.listen_udp_port`

Upgrade from old version: `static_config.debug-listen-port`

**默认值**:
```yaml
global:
  self_monitoring:
    debug:
      listen_udp_port: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 65535] |

**详细描述**:

Default value `0` means use a random client port number.
Only available for Trident (Golang version of Agent).

#### 启用调试指标 {#global.self_monitoring.debug.debug_metrics_enabled}

**标签**:

<mark>agent_restart</mark>

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

Only available for Trident (Golang version of Agent).

## 独立运行模式 {#global.standalone_mode}

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

When deepflow-agent runs in standalone mode, it will not be controlled by
deepflow-server, and the collected data will only be written to the local file.
Currently supported data types for writing are l4_flow_log and l7_flow_log. Each
type of data is written to a separate file. This configuration can be used to
specify the maximum size of the data file, and rotate when it exceeds this size.
A maximum of two files are kept for each type of data.

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

Directory where data files are written to.

### 日志文件 {#global.standalone_mode.log_file}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`global.standalone_mode.log_file`

Upgrade from old version: `static_config.log-file`

**默认值**:
```yaml
global:
  standalone_mode:
    log_file: /var/log/deepflow_agent/deepflow_agent.log
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

Note that this configuration is only used in standalone mode.

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

Only make sense when agent type is one of CHOST_VM, CHOST_BM, K8S_VM, K8S_BM.

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

The /proc fs mount path.

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

The interval of socket info sync.

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

Socket and Process uptime threshold

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

Execute the command every time when scan the process, expect get the process tag
from stdout in yaml format, the example yaml format as follow:
```
- pid: 1
  tags:
  - key: xxx
    value: xxx
- pid: 2
  tags:
  - key: xxx
    value: xxx
```
Example configuration: `os_app_tag_exec: ["cat", "/tmp/tag.yaml"]`

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

The user who should execute the `os-app-tag-exec` command.

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
  [process_name, cmdline, parent_process_name, tag]
- ignore: Whether to ignore when regex match, default value is `false`
- rewrite_name: The name will replace the process name or cmd use regexp replace.
  Default value `""` means no replacement.

Example:
```
os_proc_regex:
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
| proc.proc_event // XXX | |
| ebpf.socket.uprobe.golang | |
| ebpf.socket.uprobe.tls | |
| ebpf.socket.uprobe.rdma // XXX | |
| ebpf.file.io_event | |
| ebpf.file.management_event // XXX | |
| ebpf.profile.on_cpu | |
| ebpf.profile.off_cpu | |
| ebpf.profile.mem // XXX | |
| ebpf.profile.cuda // XXX | |
| ebpf.profile.hbm // XXX | |

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

Whether to enable Golang-specific symbol table parsing.

This feature acts on Golang processes that have trimmed the standard symbol
table. When this feature is enabled, for processes with Golang
version >= 1.13 and < 1.18, when the standard symbol table is missing, the
Golang-specific symbol table will be parsed to complete uprobe data collection.
Note that enabling this feature may cause the eBPF initialization process to
take ten minutes. The `golang-symbol` configuration item depends on the `golang`
configuration item, the `golang-symbol` is a subset of the `golang` configuration item.

Example:
- Ensure that the regular expression matching for the 'golang' configuration
  item is enabled, for example: `golang: .*`
- You've encountered the following warning log:
  ```
  [eBPF] WARNING: func resolve_bin_file() [user/go_tracer.c:558] Go process pid 1946
  [path: /proc/1946/root/usr/local/bin/kube-controller-manager] (version: go1.16). Not find any symbols!
  ```
  Suppose there is a Golang process with a process ID of '1946.'
- To initially confirm whether the executable file for this process has a symbol table:
  - Retrieve the executable file's path using the process ID:
    ```
    # ls -al /proc/1946/exe
    /proc/1946/exe -> /usr/local/bin/kube-controller-manager
    ```
  - Check if there is a symbol table:
    ```
    # nm /proc/1946/root/usr/local/bin/kube-controller-manager
    nm: /proc/1946/root/usr/local/bin/kube-controller-manager: no symbols
    ```
- If "no symbols" is encountered, it indicates the absence of a symbol table. In such a
  scenario, we need to configure the "golang-symbol" setting.
- During the agent startup process, you will observe the following log information: (The entry
  address for the function `crypto/tls.(*Conn).Write` has already been resolved, i.e., entry:0x25fca0).
  ```
  [eBPF] INFO Uprobe [/proc/1946/root/usr/local/bin/kube-controller-manager] pid:1946 go1.16.0
  entry:0x25fca0 size:1952 symname:crypto/tls.(*Conn).Write probe_func:uprobe_go_tls_write_enter rets_count:0
  ```
  The logs indicate that the Golang program has been successfully hooked.

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
        refresh_defer_duration: 600s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['5s', '3600s'] |

**详细描述**:

When deepflow-agent finds that an unresolved function name appears in the function call
stack of a Java process, it will trigger the regeneration of the symbol file of the
process. Because Java utilizes the Just-In-Time (JIT) compilation mechanism, to obtain
more symbols for Java processes, the regeneration will be deferred for a period of time.

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

All Java symbol files are stored in the '/tmp' directory mounted by the deepflow-agent.
To prevent excessive occupation of host node space due to large Java symbol files, a
maximum size limit is set for each generated Java symbol file.

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

Mirror mode is used when deepflow-agent cannot directly capture the traffic from
the source. For example:
- in the K8s macvlan environment, capture the Pod traffic through the Node NIC
- in the Hyper-V environment, capture the VM traffic through the Hypervisor NIC
- in the ESXi environment, capture traffic through VDS/VSS local SPAN
- in the DPDK environment, capture traffic through DPDK ring buffer
Use Physical Mirror mode when deepflow-agent captures traffic through physical
switch mirroring.

<mark>`Physical Mirror` is only supported in the Enterprise Edition.</mark>

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

Regular expression of NIC name for collecting traffic.

Explanation of the default configuration:
```
Localhost:     lo
Common NIC:    eth.*|en[osipx].*
QEMU VM NIC:   tap.*
Flannel:       veth.*
Calico:        cali.*
Cilium         lxc.*
Kube-OVN       [0-9a-f]+_h$
```

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

The slave interfaces of one bond interface.

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

Packet will be captured in regex matched namespaces besides the default
namespace. NICs captured in extra namespaces are also filtered with
`tap_interface_regex`.

Default value `""` means no extra network namespace (default namespace only).

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

If not configured, all traffic will be collected. Please
refer to BPF syntax: https://biot.com/capstats/bpf.html

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

#### 物理网络镜像流量中的 VLAN PCP {#inputs.cbpf.af_packet.vlan_pap_in_physical_mirror_traffic}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.af_packet.vlan_pap_in_physical_mirror_traffic`

Upgrade from old version: `static_config.mirror-traffic-pcp`

**默认值**:
```yaml
inputs:
  cbpf:
    af_packet:
      vlan_pap_in_physical_mirror_traffic: 0
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 8] |

**详细描述**:

Calculate `capture_network_type` from vlan tag only if vlan pcp matches this value.

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

It is found that there may be bugs in BPF traffic filtering under some
versions of Linux Kernel. After this configuration is enabled, deepflow-agent
will not use the filtering capabilities of BPF, and will filter by itself after
capturing full traffic. Note that this may significantly increase the resource
overhead of deepflow-agent.

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

AF_PACKET socket version in Linux environment.

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

When capture_mode != 2, you need to explicitly turn on this switch to
configure 'afpacket-blocks'.

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

deepflow-agent will automatically calculate the number of blocks
used by AF_PACKET according to max_memory, which can also be specified
using this configuration item. The size of each block is fixed at 1MB.

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

The configuration takes effect when capture_mode is 0 and extra_netns_regex is null,
PACKET_FANOUT is to enable load balancing and parallel processing, which can improve
the performance and scalability of network applications. When the `local-dispatcher-count`
is greater than 1, multiple dispatcher threads will be launched, consuming more CPU and
memory. Increasing the `local-dispatcher-count` helps to reduce the operating system's
software interrupts on multi-core CPU servers.

Attention: only valid for `traffic_capture_mode` = Local

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

The configuration is a parameter used with the PACKET_FANOUT feature in the Linux
kernel to specify the desired packet distribution algorithm. Refer to:
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

The DPDK RecvEngine is only started when this configuration item is turned on.
Note that you also need to set capture_mode to 1. Please refer to
https://dpdk-docs.readthedocs.io/en/latest/prog_guide/multi_proc_support.html

##### CPU 核心列表 {#inputs.cbpf.special_network.dpdk.cpu_core_list}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.dpdk.cpu_core_list`

Upgrade from old version: `static_config.dpdk_core_list`

**默认值**:
```yaml
inputs:
  cbpf:
    special_network:
      dpdk:
        cpu_core_list: ''
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

Map lcore set to physical cpu set.
Format: `<lcores[@cpus]>[<,lcores[@cpus]>...]`

Examples:
- 1,2,3,4
- 1-4
- (1,2)(3-10)
- 1@3,2@4

lcores and cpus list are grouped by `(` and `)`. Within the group, `-` is used
for range separator, `,` is used for single number separator. `()` can be
omitted for single element group, `@` can be omitted if cpus and lcores have
the same value.

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

Supports running on Windows and Linux, Low performance when using multiple interfaces.
Default to true in Windows, false in Linux.

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

Supports running on Linux with mirror mode.

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

This feature is only supported by the Enterprise Edition of Trident.
In general, sFlow uses port 6343. Default value `[]` means that no sFlow
data will be collected.

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

This feature is only supported by the Enterprise Edition of Trident.
Additionally, only NetFlow v5 is currently supported. In general, NetFlow
uses port 2055. Default value `[]` means that no NetFlow data will be collected.

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

The configuration takes effect when capture_mode is 0 or 2,
dispatcher-queue is always true when capture_mode is 2

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

DPDK environment does not support this configuration.

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

Larger value will reduce memory allocation for raw packet, but will also
delay memory free.

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

The length of the following queues (only for capture_mode = 2):
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
      max_capture_pps: 200
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Kpps |
| Range | [1, 1000000] |

**详细描述**:

Maximum packet rate allowed for collection.

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

Decapsulation tunnel protocols.

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

Whether to remove the tunnel header in mirrored traffic.

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

deepflow-agent will mark the TAP (Traffic Access Point) location
according to the outer vlan tag in the mirrored traffic of the physical
switch. When the vlan tag has no corresponding TAP value, or the vlan
pcp does not match the 'mirror-traffic-pcp', it will assign the TAP value.
This configuration item. Default value `3` means Cloud Network.

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

Whether to enable mirror traffic deduplication when capture_mode = 2.

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

Whether it is the mirrored traffic of NFVGW (cloud gateway).

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

Whether to enable eBPF features.

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

Whether golang process enables HTTP2/HTTPS protocol data collection
and auto-tracing. go auto-tracing also dependent go-tracing-timeout.

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

The expected maximum time interval between the server receiving the request and returning
the response, If the value is 0, this feature is disabled. Tracing only considers the
thread number.

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

Whether the process that uses the openssl library to enable HTTPS protocol data collection.
One can use the following method to determine whether an application process can use
`Uprobe hook openssl library` to access encrypted data:

Use the command `cat /proc/<PID>/maps | grep "libssl.so"` to check if it contains
information about openssl. If it does, it indicates that this process is using the
openssl library. After configuring the openssl options, deepflow-agent will retrieve process
information that matches the regular expression, hooking the corresponding encryption/decryption
interfaces of the openssl library.

In the logs, you will encounter a message similar to the following:
```
[eBPF] INFO openssl uprobe, pid:1005, path:/proc/1005/root/usr/lib64/libssl.so.1.0.2k
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

TCP&UDP Port Blacklist, Priority higher than kprobe-whitelist.

Example: 80,1000-2000

##### 白名单 {#inputs.ebpf.socket.kprobe.whitelist}

###### 比啊名单 {#inputs.ebpf.socket.kprobe.whitelist.port}

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

TCP&UDP Port Whitelist, Priority lower than kprobe-blacklist.

Example: 80,1000-2000

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

Collection modes:
- 0: Indicates that no IO events are collected.
- 1: Indicates that only IO events within the request life cycle are collected.
- 2: Indicates that all IO events are collected.

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

Only collect IO events with delay exceeding this threshold.

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

eBPF On-CPU profile switch.

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

eBPF On-CPU profile sampling frequency.

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

Whether to obtain the value of CPUID and decide whether to participate in aggregation.
- Set to 1: Obtain the value of CPUID and will be included in the aggregation of stack
  trace data.
- Set to 0: It will not be included in the aggregation. Any other value is considered
  invalid, the CPU value for stack trace data reporting is a special value
  `CPU_INVALID: 0xfff` used to indicate that it is an invalid value.

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
        disabled: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

eBPF Off-CPU profile switch.

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

Whether to obtain the value of CPUID and decide whether to participate in aggregation.
- Set to 1: Obtain the value of CPUID and will be included in the aggregation of stack
  trace data.
- Set to 0: It will not be included in the aggregation. Any other value is considered
  invalid, the CPU value for stack trace data reporting is a special value
  `CPU_INVALID: 0xfff` used to indicate that it is an invalid value.

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

If set to 0, there will be no minimum value limitation. Scheduler events are still
high-frequency events, as their rate may exceed 1 million events per second, so
caution should still be exercised.

If overhead remains an issue, you can configure the 'minblock' tunable parameter here.
If the off-CPU time is less than the value configured in this item, the data will be
discarded. If your goal is to trace longer blocking events, increasing this parameter
can filter out shorter blocking events, further reducing overhead. Additionally, we
will not collect events with a blocking time exceeding 1 hour.

### 调优 {#inputs.ebpf.tunning}

#### 最大采集速率 {#inputs.ebpf.tunning.max_capture_rate}

**标签**:

`hot_update`

**FQCN**:

`inputs.ebpf.tunning.max_capture_rate`

Upgrade from old version: `static_config.ebpf.global-ebpf-pps-threshold`

**默认值**:
```yaml
inputs:
  ebpf:
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

Default value `0` means no limitation.

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

The length of the following queues:
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

The number of worker threads refers to how many threads participate
in data processing in user-space. The actual maximal value is the number
of CPU logical cores on the host.

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

The number of page occupied by the shared memory of the kernel. The
value is `2^n (5 <= n <= 13)`. Used for perf data transfer. If the
value is between `2^n` and `2^(n+1)`, it will be automatically adjusted
by the ebpf configurator to the minimum value `2^n`.

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

The size of the ring cache queue, The value is `2^n (13 <= n <= 17)`.
If the value is between `2^n` and `2^(n+1)`, it will be automatically
adjusted by the ebpf configurator to the minimum value `2^n`.

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

Set the maximum value of hash table entries for socket tracking, depending
on the number of concurrent requests in the actual scenario

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

The threshold for cleaning socket map table entries.

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

Set the maximum value of hash table entries for thread/coroutine tracking sessions.

### 预处理 {#inputs.ebpf.preprocess}

#### 乱序重排（OOOR）缓冲区大小 {#inputs.ebpf.preprocess.out_of_order_reassembly_cache_size}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.preprocess.out_of_order_reassembly_cache_size`

Upgrade from old version: `static_config.ebpf.syscall-out-of-order-cache-size`

**默认值**:
```yaml
inputs:
  ebpf:
    preprocess:
      out_of_order_reassembly_cache_size: 16
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8, 1024] |

**详细描述**:

OOOR: Out Of Order Reassembly

When `syscall-out-of-order-reassembly` is enabled, up to `syscall-out-of-order-cache-size`
eBPF socket events (each event consuming up to `l7_log_packet_size` bytes) will be cached
in each TCP/UDP flow to prevent out-of-order events from impacting application protocol
parsing. Since eBPF socket events are sent to user space in batches, out-of-order scenarios
mainly occur when requests and responses within a single session are processed by different
CPUs, causing the response to reach user space before the request.

#### 乱序重排（OOOR）协议列表 {#inputs.ebpf.preprocess.out_of_order_reassembly_protocols}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.preprocess.out_of_order_reassembly_protocols`

Upgrade from old version: `static_config.ebpf.syscall-out-of-order-reassembly`

**默认值**:
```yaml
inputs:
  ebpf:
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

OOOR: Out Of Order Reassembly

When this capability is enabled for a specific application protocol, the agent will add
out-of-order-reassembly processing for it. Note that the agent will consume more memory
in this case, so please adjust the syscall-out-of-order-cache-size accordingly and monitor
the agent's memory usage.

Supported protocols: https://www.deepflow.io/docs/features/l7-protocols/overview/

Attention: use `HTTP2` for `gRPC` Protocol.

#### 分段重组（SR）协议列表 {#inputs.ebpf.preprocess.segmentation_reassembly_protocols}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.preprocess.segmentation_reassembly_protocols`

Upgrade from old version: `static_config.ebpf.syscall-segmentation-reassembly`

**默认值**:
```yaml
inputs:
  ebpf:
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

SR: Segmentation Reassembly

When this capability is enabled for a specific application protocol, the agent will add
segmentation-reassembly processing to merge application protocol content spread across
multiple syscalls before parsing it. This enhances the success rate of application
protocol parsing. Note that `syscall-out-of-order-reassembly` must also be enabled for
this feature to be effective.

Supported protocols: https://www.deepflow.io/docs/features/l7-protocols/overview/

Attention: use `HTTP2` for `gRPC` Protocol.

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

The interval at which deepflow-agent actively reports resource information
to deepflow-server.

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

When enabled, deepflow-agent will automatically synchronize virtual
machine and network information on the KVM (or Host) to deepflow-server.

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

How to extract the real MAC address of the virtual machine when the
agent runs on the KVM host.

Explanation of the options:
- 0: extracted from tap interface MAC address
- 1: extracted from tap interface name
- 2: extracted from the XML file of the virtual machine

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

VM XML file directory.

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

The MAC address mapping relationship of TAP NIC in complex environment can be
constructed by writing a script. The following conditions must be met to use this
script:
1. if_mac_source = 2
2. tap_mode = 0
3. The name of the TAP NIC is the same as in the virtual machine XML file
4. The format of the script output is as follows:
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

Used when deepflow-agent has only one k8s namespace query permission.

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

The schematics of entries in list is:
```
name: string
group: string
version: string
disabled: bool (default false)
field-selector: string
```

To disable a resource, add an entry to the list with `disabled: true`:
```
kubernetes-resources:
- name: services
  disabled: true
```

To enable a resource, add an entry of this resource to the list. Be advised that
this setting overrides the default of the same resource. For example, to enable
`statefulsets` in both group `apps` (the default) and `apps.kruise.io` will require
two entries:
```
kubernetes-resources:
- name: statefulsets
  group: apps
- name: statefulsets
  group: apps.kruise.io
  version: v1beta1
```

To watching `routes` in openshift you can use the following settings:
```
kubernetes-resources:
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

Used when limit k8s api list entry size.

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

Interval of listing resource when watcher idles

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

In active mode, deepflow-agent enters the netns of other Pods through
setns syscall to query the MAC and IP addresses. In this mode, the setns
operation requires the SYS_ADMIN permission. In passive mode deepflow-agent
calculates the MAC and IP addresses used by Pods by capturing ARP/ND traffic.
When set to adaptive, active mode will be used first.

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

Default value `0` means all domains, or can be set to a list of lcuuid of a
series of domains, you can get lcuuid through 'deepflow-ctl domain list'.

Note: The list of MAC and IP addresses is used by deepflow-agent to inject tags
into data. This configuration can reduce the number and frequency of MAC and
IP addresses delivered by deepflow-server to deepflow-agent. When there is no
cross-domain service request, deepflow-server can be configured to only deliver
the information in the local domain to deepflow-agent.

#### K8s 内部 Pod IP 过滤器 {#inputs.resources.pull_resource_from_controller.kubernetes_internal_pod_ip_filter}

**标签**:

`hot_update`

**FQCN**:

`inputs.resources.pull_resource_from_controller.kubernetes_internal_pod_ip_filter`

Upgrade from old version: `pod_cluster_internal_ip`

**默认值**:
```yaml
inputs:
  resources:
    pull_resource_from_controller:
      kubernetes_internal_pod_ip_filter: 0
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | 所有 K8s 集群 |
| 1 | 本地 K8s 集群 |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**详细描述**:

The list of MAC and IP addresses is used by deepflow-agent to inject tags
into data. This configuration can reduce the number and frequency of MAC and IP
addresses delivered by deepflow-server to deepflow-agent. When the Pod IP is not
used for direct communication between the K8s cluster and the outside world,
deepflow-server can be configured to only deliver the information in the local
K8s cluster to deepflow-agent.

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

Whether to enable receiving external data sources such as Prometheus,
Telegraf, OpenTelemetry, and SkyWalking.

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

Listen port of the data integration socket.

### 数据压缩 {#inputs.integration.data_compression}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.data_compression`

Upgrade from old version: `static_config.external-agent-http-proxy-compressed`

**默认值**:
```yaml
inputs:
  integration:
    data_compression: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

Whether to compress the integrated data received by deepflow-agent. Currently,
only opentelemetry data is supported, and the compression ratio is about 5:1~10:1.
Turning on this feature will result in higher CPU consumption of deepflow-agent.

### Prometheus 额外 Label {#inputs.integration.prometheus_extra_labels}

Support for getting extra labels from headers in http requests from RemoteWrite.

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

Prometheus extra labels switch.

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

Labels list. Labels in this list are sent. Label is a string
matching the regular expression `[a-zA-Z_][a-zA-Z0-9_]*`

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

The size limit of the parsed key.

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

The size limit of the parsed value.

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

When set to 0, deepflow-agent will automatically adjust the map size
according to max_memory.

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

When set to true, deepflow-agent will not use fast path.

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

When this value is larger, the more memory usage may be.

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

When this value is larger, the memory overhead is smaller, but the
performance of policy matching is worse.

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

When generating TCP header data, each flow uses one block to compress and
store multiple TCP headers, and the block size can be set here.

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

The length of the following queues (to UniformCollectSender):
- 1-packet-sequence-block-to-uniform-collect-sender

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

The number of replicas for each output queue of the PacketSequence.

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

packet-sequence-flag determines which fields need to be reported, the default
value is 0, which means the feature is disabled, and 255, which means all fields
need to be reported all fields corresponding to each bit:
```
| FLAG | SEQ | ACK | PAYLOAD_SIZE | WINDOW_SIZE | OPT_MSS | OPT_WS | OPT_SACK |
8      7     6     5              4             3         2        1          0
```

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

The length of the following queues:
- 1-mini-meta-packet-to-pcap

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

Buffer flushes when one of the flows reach this limit.

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

Buffer flushes when total data size reach this limit,
cannot exceed sender buffer size 128K.

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

Flushes a flow if its first packet were older then this interval.

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

FIXME

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

Size of tcp option address info cache size.

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

deepflow-agent will mark the long live stream and application protocol for each
<vpc, ip, protocol, port> tuple, when the traffic corresponding to a tuple fails
to be identified for many times (for multiple packets, Socket Data, Function Data),
the tuple will be marked as an unknown type to avoid deepflow-agent continuing to
try (incurring significant computational overhead) until the duration exceeds
l7-protocol-inference-ttl.

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

deepflow-agent will mark the application protocol for each
<vpc, ip, protocol, port> tuple. In order to avoid misidentification caused by IP
changes, the validity period after successfully identifying the protocol will be
limited to this value.

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

Turning off some protocol identification can reduce deepflow-agent resource consumption.

Supported protocols: https://www.deepflow.io/docs/features/l7-protocols/overview/

<mark>Oracle and TLS is only supported in the Enterprise Edition.</mark>

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

Whether the oracle integer encode is big endian.

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

Whether the oracle integer encode is compress.

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

Due to the response with data id 0x04 has different struct in
different version, it may has one byte before row affect.

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

Port-list example: 80,1000-2000

HTTP2 and TLS are only used for kprobe, not applicable to uprobe.
All data obtained through uprobe is not subject to port restrictions.

Supported protocols: https://www.deepflow.io/docs/features/l7-protocols/overview/

<mark>Oracle and TLS is only supported in the Enterprise Edition.</mark>

Attention: use `HTTP2` for `gRPC` Protocol.

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

Tag filter example:
```
tag_filters:
  HTTP:
    - field-name: request_resource  # endpoint, request_type, request_domain, request_resource
      operator: equal               # equal, prefix
      value: somevalue
```
A l7_flow_log blacklist can be configured for each protocol, preventing request logs matching
the blacklist from being collected by the agent or included in application performance metrics.
It's recommended to only place non-business request logs like heartbeats or health checks in this
blacklist. Including business request logs might lead to breaks in the distributed tracing tree.

Supported protocols: https://www.deepflow.io/docs/features/l7-protocols/overview/

<mark>Oracle and TLS is only supported in the Enterprise Edition.</mark>

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
```
tag_filters:
  HTTP:
    - field-name: request_resource  # endpoint, request_type, request_domain, request_resource
      operator: equal               # equal, prefix
      value: somevalue
  HTTP2: []
  # other protocols ...
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

Match field value.

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

You might not be concerned about certain DNS NXDOMAIN errors and may wish to ignore
them. For example, when a K8s Pod tries to resolve an external domain name, it first
concatenates it with the internal domain suffix of the cluster and attempts to resolve
it. All these attempts will receive an NXDOMAIN reply before it finally requests the
original domain name directly, and these errors may not be of concern to you. In such
cases, you can configure their `response_result` suffix here, so that the corresponding
`response_status` in the l7_flow_log is forcibly set to `Success`.

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

The timeout of l7 log info rrt calculate, when rrt exceed the value will act as timeout and will not
calculate the sum and average and will not merge the request and response in session aggregate. the value
must greater than session aggregate SLOT_TIME (const 10s) and less than 3600 on tcp.

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

The timeout of l7 log info rrt calculate, when rrt exceed the value will act as timeout and will not
calculate the sum and average and will not merge the request and response in session aggregate. the value
must greater than session aggregate SLOT_TIME (const 10s) and less than 300 on udp.

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

l7_flow_log aggregate window.

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

It is used to extract the real client IP field in the HTTP header,
such as X-Forwarded-For, etc. Leave it empty to disable this feature.

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

It is used to extract the fields in the HTTP header that are used
to uniquely identify the same request before and after the gateway,
such as X-Request-ID, etc. This feature can be turned off by setting
it to empty.

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

Used to extract the TraceID field in HTTP and RPC headers, supports filling
in multiple values separated by commas. This feature can be turned off by
setting it to empty.

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

Used to extract the SpanID field in HTTP and RPC headers, supports filling
in multiple values separated by commas. This feature can be turned off by
setting it to empty.

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

HTTP endpoint extration is enabled by default.

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

Extract endpoint according to the following rules:
- Find a longest prefix that can match according to the principle of
  "longest prefix matching"
- Intercept the first few paragraphs in URL (the content between two
  / is regarded as one paragraph) as endpoint

By default, two segments are extracted from the URL. For example, the
URL is /a/b/c?query=xxx", whose segment is 3, extracts "/a/b" as the
endpoint.

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

HTTP URL prefix.

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

Keep how many segments.

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

Configuration to extract the customized header fields of HTTP, HTTP2, gRPC protocol etc.

Example:
```yaml
custom_fields:
  HTTP:
    - field-name: "user-agent"
    - field-name: "cookie"
```

Attention: use `HTTP2` for `gRPC` Protocol.

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

Configuration to extract the customized header fields of HTTP, HTTP2, gRPC protocol etc.

Example:
```yaml
custom_fields:
  HTTP:
    - field-name: "user-agent"
    - field-name: "cookie"
  HTTP2: []
```

Attention: use `HTTP2` for `gRPC` Protocol.

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

Field name.

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

For the sake of data security, the data of the protocol that needs
to be desensitized is configured here and is not processed by default.

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

The maximum data length used for application protocol identification,
note that the effective value is less than or equal to the value of
capture_packet_size.

NOTE: For eBPF data, the largest valid value is 16384.

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

By default, unidirectional l7_flow_log is aggregated into bidirectional
request_log (session) with a caching time window of 2 minutes. During this
period, every 5 seconds is considered as a time slot (i.e., a LRU). This
configuration is used to specify the maximum number of unidirectional l7_flow_log
entries that can be cached in each time slot.

If the number of l7_flow_log entries cached in a time slot exceeds this
configuration, 10% of the data in that time slot will be evicted based on the
LRU strategy to reduce memory consumption. Note that the evicted data will not be
discarded; instead, they will be sent to the deepflow-server as unidirectional
request_log.

The following metrics can be used as reference data for adjusting this configuration:
- Metric `deepflow_system.deepflow_agent_l7_session_aggr.cached-request-resource`
  Used to record the total memory occupied by the request_resource field of the
  unidirectional l7_flow_log cached in all time slots at the current moment, in bytes.
- Metric `deepflow_system.deepflow_agent_l7_session_aggr.over-limit`
  Used to record the number of times eviction is triggered due to reaching the
  LRU capacity limit.

## Flow 性能指标 {#processors.flow_metrics}

### 时间窗口 {#processors.flow_metrics.time_window}

#### 最大可容忍的 Packet 延迟 {#processors.flow_metrics.time_window.max_tolerable_packet_delay}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.time_window.max_tolerable_packet_delay`

Upgrade from old version: `static_config.packet-delay`

**默认值**:
```yaml
processors:
  flow_metrics:
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

#### 额外可容忍的 Flow 延迟 {#processors.flow_metrics.time_window.extra_tolerable_flow_delay}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.time_window.extra_tolerable_flow_delay`

Upgrade from old version: `static_config.second-flow-extra-delay-second`

**默认值**:
```yaml
processors:
  flow_metrics:
    time_window:
      extra_tolerable_flow_delay: 0s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '10s'] |

**详细描述**:

Extra tolerance for QuadrupleGenerator receiving 1s-FlowLog.

### Conntrack（即 Flow Map） {#processors.flow_metrics.conntrack}

#### Flow Flush 间隔 {#processors.flow_metrics.conntrack.flow_flush_interval}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.conntrack.flow_flush_interval`

Upgrade from old version: `static_config.flow.flush-interval`

**默认值**:
```yaml
processors:
  flow_metrics:
    conntrack:
      flow_flush_interval: 1s
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1m'] |

**详细描述**:

Flush interval of the queue connected to the collector.

#### Flow 生成逻辑 {#processors.flow_metrics.conntrack.flow_generation}

##### 云流量忽略 MAC {#processors.flow_metrics.conntrack.flow_generation.cloud_traffic_ignore_mac}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.conntrack.flow_generation.cloud_traffic_ignore_mac`

Upgrade from old version: `static_config.flow.ignore-tor-mac`

**默认值**:
```yaml
processors:
  flow_metrics:
    conntrack:
      flow_generation:
        cloud_traffic_ignore_mac: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

When the MAC addresses of the two-way traffic collected at the same
location are asymmetrical, the traffic cannot be aggregated into a Flow.
You can set this value at this time. Only valid for Cloud (not IDC) traffic.

##### 忽略 L2End {#processors.flow_metrics.conntrack.flow_generation.ignore_l2_end}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.conntrack.flow_generation.ignore_l2_end`

Upgrade from old version: `static_config.flow.ignore-l2-end`

**默认值**:
```yaml
processors:
  flow_metrics:
    conntrack:
      flow_generation:
        ignore_l2_end: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

For Cloud traffic, only the MAC address corresponding to the side with
L2End = true is matched when generating the flow. Set this value to true to
force a double-sided MAC address match and only aggregate traffic with
exactly equal MAC addresses.

##### IDC 流量忽略 VLAN {#processors.flow_metrics.conntrack.flow_generation.idc_traffic_ignore_vlan}

**标签**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.flow_metrics.conntrack.flow_generation.idc_traffic_ignore_vlan`

Upgrade from old version: `static_config.flow.ignore-idc-vlan`

**默认值**:
```yaml
processors:
  flow_metrics:
    conntrack:
      flow_generation:
        idc_traffic_ignore_vlan: false
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**详细描述**:

When the VLAN of the two-way traffic collected at the same location
are asymmetrical, the traffic cannot be aggregated into a Flow. You can
set this value at this time. Only valid for IDC (not Cloud) traffic.

#### 超时设置 {#processors.flow_metrics.conntrack.timeouts}

##### Established {#processors.flow_metrics.conntrack.timeouts.established}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.conntrack.timeouts.established`

Upgrade from old version: `static_config.flow.established-timeout`

**默认值**:
```yaml
processors:
  flow_metrics:
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

Timeouts for TCP State Machine - Established.

##### Closing RST {#processors.flow_metrics.conntrack.timeouts.closing_rst}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.conntrack.timeouts.closing_rst`

Upgrade from old version: `static_config.flow.closing-rst-timeout`

**默认值**:
```yaml
processors:
  flow_metrics:
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

Timeouts for TCP State Machine - Closing Reset.

##### Opening RST {#processors.flow_metrics.conntrack.timeouts.opening_rst}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.conntrack.timeouts.opening_rst`

Upgrade from old version: `static_config.flow.opening-rst-timeout`

**默认值**:
```yaml
processors:
  flow_metrics:
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

Timeouts for TCP State Machine - Opening Reset.

##### Others {#processors.flow_metrics.conntrack.timeouts.others}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.conntrack.timeouts.others`

Upgrade from old version: `static_config.flow.others-timeout`

**默认值**:
```yaml
processors:
  flow_metrics:
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

Timeouts for TCP State Machine - Others.

### 调优 {#processors.flow_metrics.tunning}

#### FlowMap 哈希桶 {#processors.flow_metrics.tunning.flow_map_hash_slots}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.tunning.flow_map_hash_slots`

Upgrade from old version: `static_config.flow.flow-slots-size`

**默认值**:
```yaml
processors:
  flow_metrics:
    tunning:
      flow_map_hash_slots: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

Since FlowAggregator is the first step in all processing, this value
is also widely used in other hash tables such as QuadrupleGenerator,
Collector, etc.

#### 并发 Flow 数量限制 {#processors.flow_metrics.tunning.concurrent_flow_limit}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.tunning.concurrent_flow_limit`

Upgrade from old version: `static_config.flow.flow-count-limit`

**默认值**:
```yaml
processors:
  flow_metrics:
    tunning:
      concurrent_flow_limit: 65535
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

Maximum number of flows that can be stored in FlowMap, It will also affect the capacity of
the RRT cache, Example: rrt-cache-capacity = flow-count-limit. When rrt-cache-capacity is
not enough, it will be unable to calculate the rrt of l7.

#### 内存池大小 {#processors.flow_metrics.tunning.memory_pool_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.tunning.memory_pool_size`

Upgrade from old version: `static_config.flow.memory-pool-size`

**默认值**:
```yaml
processors:
  flow_metrics:
    tunning:
      memory_pool_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

This value is used to set max length of memory pool in FlowMap
Memory pools are used for frequently create and destroy objects like
FlowNode, FlowLog, etc.

#### Batched Buffer 最大大小 {#processors.flow_metrics.tunning.max_batched_buffer_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.tunning.max_batched_buffer_size`

Upgrade from old version: `static_config.batched-buffer-size-limit`

**默认值**:
```yaml
processors:
  flow_metrics:
    tunning:
      max_batched_buffer_size: 131072
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**详细描述**:

Only TaggedFlow allocation is affected at the moment.
Structs will be allocated in batch to minimalize malloc calls.
Total memory size of a batch will not exceed this limit.
A number larger than 128K is not recommended because the default
MMAP_THRESHOLD is 128K, allocating chunks larger than 128K will
result in calling mmap and more page faults.

#### FlowAggregator 队列大小 {#processors.flow_metrics.tunning.flow_aggregator_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.tunning.flow_aggregator_queue_size`

Upgrade from old version: `static_config.flow.flow-aggr-queue-size`

**默认值**:
```yaml
processors:
  flow_metrics:
    tunning:
      flow_aggregator_queue_size: 65535
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

The length of the following queues:
- 2-second-flow-to-minute-aggrer

#### FlowGenerator 队列大小 {#processors.flow_metrics.tunning.flow_generator_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.tunning.flow_generator_queue_size`

Upgrade from old version: `static_config.flow-queue-size`

**默认值**:
```yaml
processors:
  flow_metrics:
    tunning:
      flow_generator_queue_size: 65536
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**详细描述**:

The length of the following queues:
- 1-tagged-flow-to-quadruple-generator
- 1-tagged-flow-to-app-protocol-logs
- 0-{flow_type}-{port}-packet-to-tagged-flow (flow_type: sflow, netflow)

#### QuadrupleGenerator 队列大小 {#processors.flow_metrics.tunning.quadruple_generator_queue_size}

**标签**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_metrics.tunning.quadruple_generator_queue_size`

Upgrade from old version: `static_config.quadruple-queue-size`

**默认值**:
```yaml
processors:
  flow_metrics:
    tunning:
      quadruple_generator_queue_size: 262144
```

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [262144, 64000000] |

**详细描述**:

The length of the following queues:
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

It can only be set to FILE in standalone mode, in which case
l4_flow_log and l7_flow_log will be written to local files.

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

RAW_UDP uses RawSocket to send UDP packets, which has the highest
performance, but there may be compatibility issues in some environments.

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

When sender uses RAW_UDP to send data, this feature can be enabled to
improve performance. Linux Kernel >= 3.14 is required. Note that the data
sent when this feature is enabled cannot be captured by tcpdump.

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

The list of TAPs to collect l4_flow_log, you can also set a list of TAPs to
be collected.

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

The list of TAPs to collect l7_flow_log, you can also set a list of TAPs to
be collected.

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

Use the value of tap_side to control which l4_flow_log should be ignored for
collection. This configuration also applies to tcp_sequence and pcap data in
the Enterprise Edition. Default value `[]` means store everything.

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

Use the value of tap_side to control which l7_flow_log should be ignored for
collection.

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

The maximum number of rows of l4_flow_log sent per second, when the actual
number of rows exceeds this value, sampling is triggered.

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

The maximum number of rows of l7_flow_log sent per second, when the actual
number of rows exceeds this value, sampling is triggered.

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

The length of the following queues:
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

The number of replicas for each output queue of the
FlowAggregator/SessionAggregator.

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

When disabled, deepflow-agent will not send metrics and logging data
collected using eBPF and cBPF.

Attention: set to false will also disable l4_flow_log and l7_flow_log.

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

When enabled, deepflow-agent will not generate detailed metrics for each
inactive port (ports that only receive data, not send data), and the data of
all inactive ports will be aggregated into the metrics with a tag
'server_port = 0'.

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

When enabled, deepflow-agent will not generate detailed metrics for each
inactive IP address (IP addresses that only receive data, not send data), and
the data of all inactive IP addresses will be aggregated into the metrics with
a tag 'ip = 0'.

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

When closed, deepflow-agent only collects some basic throughput metrics.

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

When closed, deepflow-agent will not collect RED (request/error/delay) metrics.

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

Second granularity metrics.

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

The length of the following queues:
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

The number of replicas for each output queue of the collector.

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

Maximum MTU allowed when using UDP to transfer data.

Attention: Public cloud service providers may modify the content of the
tail of the UDP packet whose packet length is close to 1500 bytes. When
using UDP transmission, it is recommended to set a slightly smaller value.

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

When using RAW_UDP Socket to transmit UDP data, this value can be used to
set the VLAN tag. Default value `0` means no VLAN tag.

### Socket 类型 {#outputs.npb.socket_type}

**标签**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.socket_type`

Upgrade from old version: `npb_socket_type`

**默认值**:
```yaml
outputs:
  npb:
    socket_type: RAW_UDP
```

**枚举可选值**:
| Value | Note                         |
| ----- | ---------------------------- |
| UDP | |
| RAW_UDP | |

**模式**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**详细描述**:

RAW_UDP uses RawSocket to send UDP packets, which has the highest
performance, but there may be compatibility issues in some environments.

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

Whether to add an extra 802.1Q header to NPB traffic, when this value is
set, deepflow-agent will insert a VLAN Tag into the NPB traffic header, and
the value is the lower 12 bits of TunnelID in the VXLAN header.

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

Whether to enable global (distributed) traffic deduplication for the
NPB feature.

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

Server port for NPB.

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

NPB uses the first byte of the VXLAN Flag to identify the sending traffic to
prevent the traffic sent by NPB from being collected by deepflow-agent.

Attention: To ensure that the VNI bit is set, the value configured here will
be used after |= 0b1000_0000. Therefore, this value cannot be directly
configured as 0b1000_0000.

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

This configuration only ignores the VLAN header in the captured original message
and does not affect the configuration item: npb_vlan_mode

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

Maximum traffic rate allowed for npb sender.

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

Wasm plugin need to load in agent

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

so plugin need to load in agent. so plugin use dlopen flag RTLD_LOCAL
and RTLD_LAZY to open the so file, it mean that the so must solve the
link problem by itself

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

Unreleased deepflow-agent features can be turned on by setting this switch.

