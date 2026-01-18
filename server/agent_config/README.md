# Global {#global}

## Limits {#global.limits}

Resource limitations

### CPU Limit {#global.limits.max_millicpus}

**Tags**:

`hot_update`

**FQCN**:

`global.limits.max_millicpus`

Upgrade from old version: `max_millicpus`

**Default value**:
```yaml
global:
  limits:
    max_millicpus: 1000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Logical Milli Cores |
| Range | [1, 100000] |

**Description**:

deepflow-agent uses cgroups to limit CPU usage.
1 millicpu = 1 millicore = 0.001 core.

### Memory Limit {#global.limits.max_memory}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.limits.max_memory`

Upgrade from old version: `max_memory`

**Default value**:
```yaml
global:
  limits:
    max_memory: 768
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [128, 100000] |

**Description**:

deepflow-agent uses cgroups to limit memory usage.

Note:
- Memory of the dedicated deepflow-agent is not limited
- Memory limits for container deepflow-agent are enforced by container
- Memory limits for container deepflow-agent in the same cluster need to be consistent

### Maximum Log Backhaul Rate {#global.limits.max_log_backhaul_rate}

**Tags**:

`hot_update`

**FQCN**:

`global.limits.max_log_backhaul_rate`

Upgrade from old version: `log_threshold`

**Default value**:
```yaml
global:
  limits:
    max_log_backhaul_rate: 36000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Lines/Hour |
| Range | [0, 1000000] |

**Description**:

deepflow-agent will send logs to deepflow-server, 0 means no limit.

### Maximum Local Log File Size {#global.limits.max_local_log_file_size}

**Tags**:

`hot_update`

**FQCN**:

`global.limits.max_local_log_file_size`

Upgrade from old version: `log_file_size`

**Default value**:
```yaml
global:
  limits:
    max_local_log_file_size: 1000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [10, 10000] |

**Description**:

The maximum disk space allowed for deepflow-agent log files.

### Local Log Retention {#global.limits.local_log_retention}

**Tags**:

`hot_update`

**FQCN**:

`global.limits.local_log_retention`

Upgrade from old version: `log_retention`

**Default value**:
```yaml
global:
  limits:
    local_log_retention: 300d
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10d', '10000d'] |

**Description**:

The retention time for deepflow-agent log files.

### Maximum Socket Count {#global.limits.max_sockets}

**Tags**:

`hot_update`

**FQCN**:

`global.limits.max_sockets`

Upgrade from old version: `static_config.max-sockets`

**Default value**:
```yaml
global:
  limits:
    max_sockets: 1024
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | count |
| Range | [16, 4096] |

**Description**:

The maximum number of sockets that the agent can open.
Agent will restart if socket count exceeds this value.

### Maximum Socket Count Tolerate Interval {#global.limits.max_sockets_tolerate_interval}

**Tags**:

`hot_update`

**FQCN**:

`global.limits.max_sockets_tolerate_interval`

Upgrade from old version: `static_config.max-sockets-tolerate-interval`

**Default value**:
```yaml
global:
  limits:
    max_sockets_tolerate_interval: 60s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0s', '3600s'] |

**Description**:

The interval to tolerate socket count exceeding max-sockets before restarting.
Agent will only restart if socket count exceeds max-sockets for this duration.
Restarts are triggered by guard module, so setting this value lower than guard-interval
will cause agent to restart immediately.

## Alerts {#global.alerts}

### Thread Limit {#global.alerts.thread_threshold}

**Tags**:

`hot_update`

**FQCN**:

`global.alerts.thread_threshold`

Upgrade from old version: `thread_threshold`

**Default value**:
```yaml
global:
  alerts:
    thread_threshold: 500
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 1000] |

**Description**:

The maximum number of threads deepflow-agent is allowed to create.
- When the number of threads exceeds this limit, an exception alert will be triggered.
- When the number of threads exceeds twice this limit value, a deepflow-agent restart will be triggered.

### Process Limit {#global.alerts.process_threshold}

**Tags**:

`hot_update`

**FQCN**:

`global.alerts.process_threshold`

Upgrade from old version: `process_threshold`

**Default value**:
```yaml
global:
  alerts:
    process_threshold: 10
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 100] |

**Description**:

The maximum number of processes named `deepflow-agent` is allowed to launch.
If the number of processes named `deepflow-agent` in the current system reaches this limit,
subsequent processes named `deepflow-agent` will fail to start.

### Core File Checker {#global.alerts.check_core_file_disabled}

**Tags**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`global.alerts.check_core_file_disabled`

Upgrade from old version: `static_config.check-core-file-disabled`

**Default value**:
```yaml
global:
  alerts:
    check_core_file_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When the host has an invalid NFS file system or a docker is running,
sometime program hang when checking the core file, so the core file
check provides a switch to prevent the process hang. Additional links:
- [https://serverfault.com/questions/367438/ls-hangs-for-a-certain-directory](https://serverfault.com/questions/367438/ls-hangs-for-a-certain-directory)
- [https://unix.stackexchange.com/questions/495854/processes-hanging-when-trying-to-access-a-file](https://unix.stackexchange.com/questions/495854/processes-hanging-when-trying-to-access-a-file)

## Circuit Breakers {#global.circuit_breakers}

Control deepflow-agent to stop running or stop some functions under certain environmental conditions.

### System Free Memory Percentage {#global.circuit_breakers.sys_memory_percentage}

Calculation Method: `(free_memory / total_memory) * 100%`

#### Trigger Threshold {#global.circuit_breakers.sys_memory_percentage.trigger_threshold}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.sys_memory_percentage.trigger_threshold`

Upgrade from old version: `sys_free_memory_limit`

**Default value**:
```yaml
global:
  circuit_breakers:
    sys_memory_percentage:
      trigger_threshold: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | % |
| Range | [0, 100] |

**Description**:

Setting it to 0 indicates that the system memory ratio is not checked.
The `observed memory ratio` is determined by `global.circuit_breakers.sys_memory_percentage.metric`.
1. When the current system `observed memory ratio` is below `trigger_threshold` * 70%,
   the agent will automatically restart.
2. When the current system `observed memory ratio` is below trigger_threshold but above 70%,
   the agent is set to the abnormal state of `FREE_MEM_EXCEEDED` and reports an alarm.
3. When the current system `observed memory ratio` remains above `trigger_threshold` * 110%,
   the agent recovers from the abnormal state.

#### Metric {#global.circuit_breakers.sys_memory_percentage.metric}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.sys_memory_percentage.metric`

Upgrade from old version: `sys_free_memory_metric`

**Default value**:
```yaml
global:
  circuit_breakers:
    sys_memory_percentage:
      metric: free
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| free | |
| available | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

deepflow-agent observes the percentage of this memory metric

### Relative System Load {#global.circuit_breakers.relative_sys_load}

Calculation Method: `system_load / total_cpu_cores`

#### Trigger Threshold {#global.circuit_breakers.relative_sys_load.trigger_threshold}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.relative_sys_load.trigger_threshold`

Upgrade from old version: `system_load_circuit_breaker_threshold`

**Default value**:
```yaml
global:
  circuit_breakers:
    relative_sys_load:
      trigger_threshold: 1.0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | float |
| Range | [0, 10] |

**Description**:

When Linux system load divided by the number of
CPU cores exceeds this value, the agent automatically enters
the disabled state.
Setting it or `recovery_threshold` to 0 disables this feature.

#### Recovery Threshold {#global.circuit_breakers.relative_sys_load.recovery_threshold}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.relative_sys_load.recovery_threshold`

Upgrade from old version: `system_load_circuit_breaker_recover`

**Default value**:
```yaml
global:
  circuit_breakers:
    relative_sys_load:
      recovery_threshold: 0.9
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | float |
| Range | [0, 10] |

**Description**:

After deepflow-agent enters disabled state and Linux system load
divided by the number of CPU cores is continuously below this value for 5
minutes, the agent can recover from the circuit breaker
disabled state.
Setting it or `trigger_threshold` to 0 disables this feature.

#### Metric {#global.circuit_breakers.relative_sys_load.metric}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.relative_sys_load.metric`

Upgrade from old version: `system_load_circuit_breaker_metric`

**Default value**:
```yaml
global:
  circuit_breakers:
    relative_sys_load:
      metric: load15
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| load1 | |
| load5 | |
| load15 | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The system load circuit breaker mechanism uses this metric,
and the agent will check this metric every 10 seconds by default.

### Tx Throughput {#global.circuit_breakers.tx_throughput}

#### Trigger Threshold {#global.circuit_breakers.tx_throughput.trigger_threshold}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`global.circuit_breakers.tx_throughput.trigger_threshold`

Upgrade from old version: `max_tx_bandwidth`

**Default value**:
```yaml
global:
  circuit_breakers:
    tx_throughput:
      trigger_threshold: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Mbps |
| Range | [0, 100000] |

**Description**:

When the outbound throughput of the NPB interface reaches or exceeds
the threshold, the broker will be stopped, after that the broker will
be resumed if the throughput is lower than
`(trigger_threshold - outputs.npb.max_tx_throughput)*90%`
within 5 consecutive monitoring intervals.

Attention: When configuring this value, it must be greater than
`outputs.npb.max_tx_throughput`. Set to 0 will disable this feature.

#### Throughput Monitoring Interval {#global.circuit_breakers.tx_throughput.throughput_monitoring_interval}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`global.circuit_breakers.tx_throughput.throughput_monitoring_interval`

Upgrade from old version: `bandwidth_probe_interval`

**Default value**:
```yaml
global:
  circuit_breakers:
    tx_throughput:
      throughput_monitoring_interval: 10s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '60s'] |

**Description**:

Monitoring interval for outbound traffic rate of NPB interface.

### Free Disk {#global.circuit_breakers.free_disk}

#### Percentage Trigger Threshold {#global.circuit_breakers.free_disk.percentage_trigger_threshold}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.free_disk.percentage_trigger_threshold`

**Default value**:
```yaml
global:
  circuit_breakers:
    free_disk:
      percentage_trigger_threshold: 15
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | % |
| Range | [0, 100] |

**Description**:

This configuration is only valid when the Agent runs in a non-container environment. Configuring to 0 means disabling the threshold.
The observed disks are the disks where the `global.circuit_breakers.free_disk.directories` are located.
1. When the system `free disk ratio` is lower than `this threshold`, the Agent enters the fuse disabled state,
   and sets the `FREE_DISK_CIRCUIT_BREAKER` abnormal state, and reports the Agent abnormal alarm.
2. When the system `free disk ratio` is higher than `this threshold * 110%`, the Agent recovers from the abnormal state.

#### Absolute_Trigger Threshold {#global.circuit_breakers.free_disk.absolute_trigger_threshold}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.free_disk.absolute_trigger_threshold`

**Default value**:
```yaml
global:
  circuit_breakers:
    free_disk:
      absolute_trigger_threshold: 10
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | GB |
| Range | [0, 100000] |

**Description**:

This configuration is only valid when the Agent runs in a non-container environment. Configuring to 0 means disabling the threshold.
The observed disks are the disks where the `global.circuit_breakers.free_disk.directories` is located.
1. When the system `free disk size` is lower than `this threshold`, the Agent enters the fuse disabled state,
   and sets the `FREE_DISK_CIRCUIT_BREAKER` abnormal state, and reports the Agent abnormal alarm.
2. When the system `free disk size` is higher than `this threshold * 110%`, the Agent recovers from the abnormal state.

#### Directories {#global.circuit_breakers.free_disk.directories}

**Tags**:

`hot_update`

**FQCN**:

`global.circuit_breakers.free_disk.directories`

**Default value**:
```yaml
global:
  circuit_breakers:
    free_disk:
      directories:
      - /
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Observe the disk space where the directories is located.
For the `windows` operating system, the default value is `c:\`.

## Tunning {#global.tunning}

Tune the runtime of deepflow-agent.

### CPU Affinity {#global.tunning.cpu_affinity}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.tunning.cpu_affinity`

Upgrade from old version: `static_config.cpu-affinity`

**Default value**:
```yaml
global:
  tunning:
    cpu_affinity: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 65536] |

**Description**:

CPU affinity is the tendency of a process to run on a given CPU for as long as possible
without being migrated to other processors. Invalid ID will be ignored. Currently only
works for dispatcher threads. Example:
```yaml
global:
  tunning:
    cpu_affinity: [1, 3, 5, 7, 9]
```

### Process Scheduling Priority {#global.tunning.process_scheduling_priority}

**Tags**:

`hot_update`

**FQCN**:

`global.tunning.process_scheduling_priority`

Upgrade from old version: `static_config.process-scheduling-priority`

**Default value**:
```yaml
global:
  tunning:
    process_scheduling_priority: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [-20, 19] |

**Description**:

The smaller the value of process scheduling priority, the higher the priority of the
`deepflow-agent` process, and the larger the value, the lower the priority.

### Idle Memory Trimming {#global.tunning.idle_memory_trimming}

**Tags**:

`hot_update`

**FQCN**:

`global.tunning.idle_memory_trimming`

Upgrade from old version: `static_config.memory-trim-disabled`

**Default value**:
```yaml
global:
  tunning:
    idle_memory_trimming: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Proactive memory trimming can effectively reduce memory usage, but there may be
performance loss.

### Turn off swap memory {#global.tunning.swap_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.tunning.swap_disabled`

**Default value**:
```yaml
global:
  tunning:
    swap_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Note that disabling swap memory requires root and CAP_IPC_LOCK permissions, and disabling
swap memory may improve performance and reduce CPU usage, but memory will increase.

### Page Cache Reclaim Percentage {#global.tunning.page_cache_reclaim_percentage}

**Tags**:

`hot_update`

**FQCN**:

`global.tunning.page_cache_reclaim_percentage`

Upgrade from old version: `static_config.page-cache-reclaim-percentage`

**Default value**:
```yaml
global:
  tunning:
    page_cache_reclaim_percentage: 100
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 100] |

**Description**:

A page cache reclaim is triggered when the pecentage of page cache and
cgroups memory.limit_in_bytes exceeds this value.
Both anonymous memory and file page cache are accounted for in cgroup's memory usage.
Under some circumstances, page cache alone can cause cgroup to OOM kill agent process.
To avoid this, agent can reclaim page cache periodically. Although reclaming may not
cause performance issues for agent who doesn't have much I/O, other processes in
the same cgroup may be affected. Very low values are not recommended.
Note:
- This feature is available for cgroups v1 only.
- This feature is disabled if agent memory cgroup path is "/".
- The minimal interval of reclaims is 1 minute.

### Resource Monitoring Interval {#global.tunning.resource_monitoring_interval}

**Tags**:

`hot_update`

**FQCN**:

`global.tunning.resource_monitoring_interval`

Upgrade from old version: `static_config.guard-interval`

**Default value**:
```yaml
global:
  tunning:
    resource_monitoring_interval: 10s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '3600s'] |

**Description**:

The agent will monitor:
1. System free memory
2. Get the number of threads of the agent itself by reading the file information
   under the /proc directory
3. Size and number of log files generated by the agent.
4. System load
5. Agent memory usage (check if memory trimming is needed)

## NTP Clock Synchronization {#global.ntp}

This synchronization mechanism does not alter the host's clock; it is only used
internally by the deepflow-agent process.

### Enabled {#global.ntp.enabled}

**Tags**:

`hot_update`

**FQCN**:

`global.ntp.enabled`

Upgrade from old version: `ntp_enabled`

**Default value**:
```yaml
global:
  ntp:
    enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to synchronize the clock to the deepflow-server, this behavior
will not change the time of the deepflow-agent running environment.

Notice: Before enabling NTP, the controller needs to first start the NTP service. The agent will
only continue to work after the time synchronization is complete.

### Maximum Drift {#global.ntp.max_drift}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.ntp.max_drift`

Upgrade from old version: `static_config.ntp-max-interval`

**Default value**:
```yaml
global:
  ntp:
    max_drift: 300s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '365d'] |

**Description**:

When the clock drift exceeds this value, the agent will restart.

### Minimal Drift {#global.ntp.min_drift}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.ntp.min_drift`

Upgrade from old version: `static_config.ntp-min-interval`

**Default value**:
```yaml
global:
  ntp:
    min_drift: 10s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '365d'] |

**Description**:

When the clock drift exceeds this value, the timestamp will be corrected.

## Communication {#global.communication}

Configuration of deepflow-agent communication.

### Proactive Request Interval {#global.communication.proactive_request_interval}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.proactive_request_interval`

Upgrade from old version: `sync_interval`

**Default value**:
```yaml
global:
  communication:
    proactive_request_interval: 60s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '3600s'] |

**Description**:

The interval at which deepflow-agent proactively requests configuration and
tag information from deepflow-server.

### Maximum Escape Duration {#global.communication.max_escape_duration}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.max_escape_duration`

Upgrade from old version: `max_escape_seconds`

**Default value**:
```yaml
global:
  communication:
    max_escape_duration: 3600s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['600s', '30d'] |

**Description**:

The maximum time that the agent is allowed to work normally when it
cannot connect to the server. After the timeout, the agent automatically
enters the disabled state.

### Controller IP Address {#global.communication.proxy_controller_ip}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.proxy_controller_ip`

Upgrade from old version: `proxy_controller_ip`

**Default value**:
```yaml
global:
  communication:
    proxy_controller_ip: 127.0.0.1
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | ip |

**Description**:

When this value is set, deepflow-agent will use this IP to access the
control plane port of deepflow-server, otherwise, the server will use
its own node IP as the control plane communication IP. This parameter is
usually used when the server uses a load balancer or a virtual IP to
provide services externally.

### Controller Port {#global.communication.proxy_controller_port}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.proxy_controller_port`

Upgrade from old version: `proxy_controller_port`

**Default value**:
```yaml
global:
  communication:
    proxy_controller_port: 30035
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

The control plane port used by deepflow-agent to access deepflow-server.
The default port within the same K8s cluster is 20035, and the default port
of deepflow-agent outside the cluster is 30035.

### Ingester IP Address {#global.communication.ingester_ip}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.ingester_ip`

Upgrade from old version: `analyzer_ip`

**Default value**:
```yaml
global:
  communication:
    ingester_ip: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | ip |

**Description**:

When this value is set, deepflow-agent will use this IP to access the
data plane port of deepflow-server, which is usually used when
deepflow-server uses an external load balancer.

### Ingester Port {#global.communication.ingester_port}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.ingester_port`

Upgrade from old version: `analyzer_port`

**Default value**:
```yaml
global:
  communication:
    ingester_port: 30033
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

The data plane port used by deepflow-agent to access deepflow-server.
The default port within the same K8s cluster is 20033, and the default port
of deepflow-agent outside the cluster is 30033.

### gRPC Socket Buffer Size {#global.communication.grpc_buffer_size}

**Tags**:

`hot_update`
<mark>deprecated</mark>

**FQCN**:

`global.communication.grpc_buffer_size`

Upgrade from old version: `static_config.grpc-buffer-size`

**Default value**:
```yaml
global:
  communication:
    grpc_buffer_size: 5
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [5, 1024] |

**Description**:

gRPC socket buffer size.

### Max Throughput To Ingester {#global.communication.max_throughput_to_ingester}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.max_throughput_to_ingester`

**Default value**:
```yaml
global:
  communication:
    max_throughput_to_ingester: 100
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Mbps |
| Range | [0, 10000] |

**Description**:

The maximum allowed flow rate for sending observability data to the server-side Ingester module.
For the overflow action, refer to the `ingester_traffic_overflow_action` configuration description.
Setting it to 0 means no speed limit.

### Action when the Ingester traffic exceeds the limit {#global.communication.ingester_traffic_overflow_action}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.ingester_traffic_overflow_action`

**Default value**:
```yaml
global:
  communication:
    ingester_traffic_overflow_action: WAIT
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| WAIT | |
| DROP | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Action when the Ingester traffic exceeds the limit
- WAIT: pause sending, cache data into queue, and wait for next sending
- DROP: the data is discarded directly and the Agent `DATA_BPS_THRESHOLD_EXCEEDED` exception is triggered

### Request via NAT IP Address {#global.communication.request_via_nat_ip}

**Tags**:

`hot_update`

**FQCN**:

`global.communication.request_via_nat_ip`

Upgrade from old version: `nat_ip_enabled`

**Default value**:
```yaml
global:
  communication:
    request_via_nat_ip: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Used when deepflow-agent uses an external IP address to access
deepflow-server. For example, when deepflow-server is behind a NAT gateway,
or the host where deepflow-server is located has multiple node IP addresses
and different deepflow-agents need to access different node IPs, you can
set an additional NAT IP for each deepflow-server address, and modify this
value to `true`.

## Self Monitoring {#global.self_monitoring}

Configuration of deepflow-agent's own diagnosis.

### Log {#global.self_monitoring.log}

Configuration of deepflow-agent's own logs.

#### Log Level {#global.self_monitoring.log.log_level}

**Tags**:

`hot_update`

**FQCN**:

`global.self_monitoring.log.log_level`

Upgrade from old version: `log_level`

**Default value**:
```yaml
global:
  self_monitoring:
    log:
      log_level: INFO
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| DEBUG | |
| INFO | |
| WARN | |
| ERROR | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Log level of deepflow-agent.

It is also possible to specify the log level for specific modules with advanced configuation in the following format:

```
<log_level_spec> ::= single_log_level_spec[{,single_log_level_spec}][/<text_filter>]
<single_log_level_spec> ::= <path_to_module>|<log_level>|<path_to_module>=<log_level>
<text_filter> ::= <regex>
```

For example:

```
log_level: info,deepflow_agent::rpc::session=debug
```

will set the log level to INFO for all modules and DEBUG for the rpc::session module.

#### Log File {#global.self_monitoring.log.log_file}

**Tags**:

`hot_update`

**FQCN**:

`global.self_monitoring.log.log_file`

Upgrade from old version: `static_config.log-file`

**Default value**:
```yaml
global:
  self_monitoring:
    log:
      log_file: /var/log/deepflow-agent/deepflow-agent.log
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The file where deepflow-agent logs are written.
Note that this configuration is only used in standalone mode.

#### Log Backhaul Enabled {#global.self_monitoring.log.log_backhaul_enabled}

**Tags**:

`hot_update`

**FQCN**:

`global.self_monitoring.log.log_backhaul_enabled`

Upgrade from old version: `rsyslog_enabled`

**Default value**:
```yaml
global:
  self_monitoring:
    log:
      log_backhaul_enabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When enabled, deepflow-agent will send its own logs to deepflow-server.

### Profile {#global.self_monitoring.profile}

#### Enabled {#global.self_monitoring.profile.enabled}

**Tags**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`global.self_monitoring.profile.enabled`

Upgrade from old version: `static_config.profiler`

**Default value**:
```yaml
global:
  self_monitoring:
    profile:
      enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Only available for Trident (Golang version of Agent).

### Debug {#global.self_monitoring.debug}

#### Enabled {#global.self_monitoring.debug.enabled}

**Tags**:

`hot_update`

**FQCN**:

`global.self_monitoring.debug.enabled`

Upgrade from old version: `debug_enabled`

**Default value**:
```yaml
global:
  self_monitoring:
    debug:
      enabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Disabled / Enabled the debug function of the deepflow-agent.

#### Local UDP Port {#global.self_monitoring.debug.local_udp_port}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.self_monitoring.debug.local_udp_port`

Upgrade from old version: `static_config.debug-listen-port`

**Default value**:
```yaml
global:
  self_monitoring:
    debug:
      local_udp_port: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 65535] |

**Description**:

Default value `0` means use a random listen port number.
Only available for Trident (Golang version of Agent).

#### Debug Metrics Enabled {#global.self_monitoring.debug.debug_metrics_enabled}

**Tags**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`global.self_monitoring.debug.debug_metrics_enabled`

Upgrade from old version: `static_config.enable-debug-stats`

**Default value**:
```yaml
global:
  self_monitoring:
    debug:
      debug_metrics_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Only available for Trident (Golang version of Agent).

### Interval {#global.self_monitoring.interval}

**Tags**:

`hot_update`

**FQCN**:

`global.self_monitoring.interval`

Upgrade from old version: `stats_interval`

**Default value**:
```yaml
global:
  self_monitoring:
    interval: 10s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '3600s'] |

**Description**:

statsd interval.

## Standalone Mode {#global.standalone_mode}

Configuration of deepflow-agent standalone mode.

### Maximum Data File Size {#global.standalone_mode.max_data_file_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.standalone_mode.max_data_file_size`

Upgrade from old version: `static_config.standalone-data-file-size`

**Default value**:
```yaml
global:
  standalone_mode:
    max_data_file_size: 200
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [1, 1000000] |

**Description**:

When deepflow-agent runs in standalone mode, it will not be controlled by
deepflow-server, and the collected data will only be written to the local file.
Currently supported data types for writing are l4_flow_log and l7_flow_log. Each
type of data is written to a separate file. This configuration can be used to
specify the maximum size of the data file, and rotate when it exceeds this size.
A maximum of two files are kept for each type of data.

### Data File Directory {#global.standalone_mode.data_file_dir}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`global.standalone_mode.data_file_dir`

Upgrade from old version: `static_config.standalone-data-file-dir`

**Default value**:
```yaml
global:
  standalone_mode:
    data_file_dir: /var/log/deepflow-agent/
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Directory where data files are written to.

# Inputs {#inputs}

## Proc {#inputs.proc}

### Enabled {#inputs.proc.enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.enabled`

Upgrade from old version: `static_config.os-proc-sync-enabled`

**Default value**:
```yaml
inputs:
  proc:
    enabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

After enabling this configuration, deepflow-agent will periodically report the process information
specified in `inputs.proc.process_matcher` to deepflow-server. After synchronizing process information,
all eBPF observability data will automatically inject the global process ID (gprocess_id) tag.

Note: When enabling this feature, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `proc.gprocess_info` must be included in `inputs.proc.process_matcher.[*].enabled_features`.

This configuration only applies to agents of `cloud server` types (CHOST_VM, CHOST_BM) and `container`
types (K8S_VM, K8S_BM). Use the command `deepflow-ctl agent list` to determine the specific agent
type in CLI environments.

### Directory of /proc {#inputs.proc.proc_dir_path}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.proc_dir_path`

Upgrade from old version: `static_config.os-proc-root`

**Default value**:
```yaml
inputs:
  proc:
    proc_dir_path: /proc
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The /proc fs mount path.

### Socket Information Synchronization Interval {#inputs.proc.socket_info_sync_interval}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.socket_info_sync_interval`

Upgrade from old version: `static_config.os-proc-socket-sync-interval`

**Default value**:
```yaml
inputs:
  proc:
    socket_info_sync_interval: 0ns
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1h'] |

**Description**:

Synchronization interval for process Socket information.

'0ns' means disabled, do not configure a value less than `1s` except for 0.

Note: When enabling this feature, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `inputs.proc.socket_info_sync_interval` must be included in `inputs.proc.process_matcher.[*].enabled_features`.
Additionally, ensure `inputs.proc.enabled` is configured to **true**.

### Minimal Lifetime {#inputs.proc.min_lifetime}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.min_lifetime`

Upgrade from old version: `static_config.os-proc-socket-min-lifetime`

**Default value**:
```yaml
inputs:
  proc:
    min_lifetime: 3s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1h'] |

**Description**:

Socket and Process will not be reported if their uptime is lower than this threshold.

### Tag Extraction {#inputs.proc.tag_extraction}

#### Script Command {#inputs.proc.tag_extraction.script_command}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.tag_extraction.script_command`

Upgrade from old version: `static_config.os-app-tag-exec`

**Default value**:
```yaml
inputs:
  proc:
    tag_extraction:
      script_command: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Execute the command every time when scan the process, expect get the process tag
from stdout in yaml format, the example yaml format as follow:
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
Example configuration:
```yaml
inputs:
  proc:
    tag_extraction:
      script_command: ["cat", "/tmp/tag.yaml"]
```

#### Execution Username {#inputs.proc.tag_extraction.exec_username}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.tag_extraction.exec_username`

Upgrade from old version: `static_config.os-app-tag-exec-user`

**Default value**:
```yaml
inputs:
  proc:
    tag_extraction:
      exec_username: deepflow
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The user who should execute the `script_command` command.

### Process Blacklist {#inputs.proc.process_blacklist}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_blacklist`

**Default value**:
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

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The list of processe names ignored by process matcher.

### Process Matcher {#inputs.proc.process_matcher}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher`

Upgrade from old version: `static_config.os-proc-regex`

**Default value**:
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

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

List of advanced features enabled for specific processes.

Will traverse over the entire array, so the previous ones will be matched first.
when match_type is parent_process_name, will recursive to match parent proc name,
and rewrite_name field will ignore. rewrite_name can replace by regexp capture group
and windows style environment variable, for example: `$1-py-script-%HOSTNAME%` will
replace regexp capture group 1 and HOSTNAME env var.

Configuration Item:
- match_regex: The regexp use for match the process, default value is `""`
- match_type: regexp match field, default value is `process_name`, options are
  [process_name, cmdline, cmdline_with_args, parent_process_name, tag]
- ignore: Whether to ignore matched processes, default value is `false`
- rewrite_name: The name will replace the process name or cmd use regexp replace.
  Default value `""` means no replacement.
- enabled_features: List of features enabled for matched processes. Available options:
  - proc.gprocess_info (Ensure `inputs.proc.enabled` is configured to **true**)
  - proc.golang_symbol_table (Ensure `inputs.proc.symbol_table.golang_specific.enabled` is configured to **true**)
  - proc.socket_list (Ensure `inputs.proc.socket_info_sync_interval` is configured to a **number > 0**)
  - ebpf.socket.uprobe.golang (Ensure `inputs.ebpf.socket.uprobe.golang.enabled` is configured to **true**)
  - ebpf.socket.uprobe.tls (Ensure `inputs.ebpf.socket.uprobe.tls.enabled` is configured to **true**)
  - ebpf.profile.on_cpu (Ensure `inputs.ebpf.profile.on_cpu.disabled` is configured to **false**)
  - ebpf.profile.off_cpu (Ensure `inputs.ebpf.profile.off_cpu.disabled` is configured to **false**)
  - ebpf.profile.memory (Ensure `inputs.ebpf.profile.memory.disabled` is configured to **false**)

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

#### Match Regex {#inputs.proc.process_matcher.match_regex}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_regex`

Upgrade from old version: `static_config.os-proc-regex.match-regex`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_regex: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The regex of matcher.

#### Match Type {#inputs.proc.process_matcher.match_type}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_type`

Upgrade from old version: `static_config.os-proc-regex.match-type`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_type: process_name
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| process_name | |
| cmdline | |
| cmdline_with_args | |
| parent_process_name | |
| tag | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The type of matcher.

#### Match Languages {#inputs.proc.process_matcher.match_languages}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_languages`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_languages: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| java | |
| golang | |
| python | |
| lua | |
| php | |
| nodejs | |
| dotnet | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Default value `[]` match all languages.

#### Match Usernames {#inputs.proc.process_matcher.match_usernames}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.match_usernames`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - match_usernames: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Default value `[]` match all usernames.

#### Only in Container {#inputs.proc.process_matcher.only_in_container}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.only_in_container`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - only_in_container: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Default value `true` means only match processes in container.

#### Only with Tag {#inputs.proc.process_matcher.only_with_tag}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.only_with_tag`

Upgrade from old version: `static_config.os-proc-sync-tagged-only`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - only_with_tag: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Default value `false` means match processes with or without tags.

#### Ignore {#inputs.proc.process_matcher.ignore}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.ignore`

Upgrade from old version: `static_config.os-proc-regex.action`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - ignore: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to ignore matched processes.

#### Rewrite Name {#inputs.proc.process_matcher.rewrite_name}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.rewrite_name`

Upgrade from old version: `static_config.os-proc-regex.rewrite-name`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - rewrite_name: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

New name after matched.

#### Enabled Features {#inputs.proc.process_matcher.enabled_features}

**Tags**:

`hot_update`

**FQCN**:

`inputs.proc.process_matcher.enabled_features`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.regex, static_config.ebpf.off-cpu-profile.regex`

**Default value**:
```yaml
inputs:
  proc:
    process_matcher:
    - enabled_features: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| proc.gprocess_info | Synchronize process resource information and inject process tags from the observation point into raw eBPF data |
| proc.golang_symbol_table | Parse Golang-specific symbol tables to optimize profiling data when Golang processes prune the standard symbol table |
| proc.socket_list | Synchronize active socket information of processes to inject process labels for both peers in application and network observation data |
| ebpf.socket.uprobe.golang | Enable eBPF uprobe for Golang processes to trace goroutines and capture Golang HTTP/2 and HTTPS communications |
| ebpf.socket.uprobe.tls | Enable eBPF uprobe for TLS communications to capture encrypted communication data from non-Golang processes |
| ebpf.profile.on_cpu | Enable continuous On-CPU profiling |
| ebpf.profile.off_cpu | Enable continuous Off-CPU profiling |
| ebpf.profile.memory | Enable continuous memory profiling |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Also ensure the global configuration parameters for related features are enabled:
- proc.gprocess_info (Ensure `inputs.proc.enabled` is configured to **true**)
- proc.golang_symbol_table (Ensure `inputs.proc.symbol_table.golang_specific.enabled` is configured to **true**)
- proc.socket_list (Ensure `inputs.proc.socket_info_sync_interval` is configured to a **number > 0**)
- ebpf.socket.uprobe.golang (Ensure `inputs.ebpf.socket.uprobe.golang.enabled` is configured to **true**)
- ebpf.socket.uprobe.tls (Ensure `inputs.ebpf.socket.uprobe.tls.enabled` is configured to **true**)
- ebpf.profile.on_cpu (Ensure `inputs.ebpf.profile.on_cpu.disabled` is configured to **false**)
- ebpf.profile.off_cpu (Ensure `inputs.ebpf.profile.off_cpu.disabled` is configured to **false**)
- ebpf.profile.memory (Ensure `inputs.ebpf.profile.memory.disabled` is configured to **false**)

### Symbol Table {#inputs.proc.symbol_table}

#### Golang-specific {#inputs.proc.symbol_table.golang_specific}

##### Enabled {#inputs.proc.symbol_table.golang_specific.enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.symbol_table.golang_specific.enabled`

Upgrade from old version: `static_config.ebpf.uprobe-process-name-regexs.golang-symbol`

**Default value**:
```yaml
inputs:
  proc:
    symbol_table:
      golang_specific:
        enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to enable Golang-specific symbol table parsing.

This feature acts on Golang processes that have trimmed the standard symbol
table. When this feature is enabled, for processes with Golang
version >= 1.13 and < 1.18, when the standard symbol table is missing, the
Golang-specific symbol table will be parsed to complete uprobe data collection.
Note that enabling this feature may cause the eBPF initialization process to
take ten minutes.

Example:
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

Note: When enabling this feature, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `proc.golang_symbol_table` must be included in `inputs.proc.process_matcher.[*].enabled_features`.

#### Java {#inputs.proc.symbol_table.java}

##### Refresh Defer Duration {#inputs.proc.symbol_table.java.refresh_defer_duration}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.proc.symbol_table.java.refresh_defer_duration`

Upgrade from old version: `static_config.ebpf.java-symbol-file-refresh-defer-interval`

**Default value**:
```yaml
inputs:
  proc:
    symbol_table:
      java:
        refresh_defer_duration: 60s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['5s', '3600s'] |

**Description**:

When the `deepflow-agent` detects unresolved function names in the Java process call stack, it
triggers the generation of the process function symbol table and updates the symbol cache. Currently,
the Java symbol file is continuously updated, and the `duration` is used to control the delay in
updating the symbol cache with the new symbol file. This delay is necessary because Java uses a JIT
(Just-In-Time) compilation mechanism, which requires a warm-up phase for symbol generation. To obtain
more complete Java symbols, the update of the Java symbol cache is deferred. This approach also helps
avoid frequent symbol cache refreshes due to missing symbols, which could otherwise result in significant
CPU resource consumption.

##### Maximum Symbol File Size {#inputs.proc.symbol_table.java.max_symbol_file_size}

**Tags**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`inputs.proc.symbol_table.java.max_symbol_file_size`

Upgrade from old version: `static_config.ebpf.java-symbol-file-max-space-limit`

**Default value**:
```yaml
inputs:
  proc:
    symbol_table:
      java:
        max_symbol_file_size: 10
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | MiB |
| Range | [2, 100] |

**Description**:

All Java symbol files are stored in the '/tmp' directory mounted by the deepflow-agent.
To prevent excessive occupation of host node space due to large Java symbol files, a
maximum size limit is set for each generated Java symbol file.

## cBPF {#inputs.cbpf}

### Common {#inputs.cbpf.common}

#### Packet Capture Mode {#inputs.cbpf.common.capture_mode}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.common.capture_mode`

Upgrade from old version: `tap_mode`

**Default value**:
```yaml
inputs:
  cbpf:
    common:
      capture_mode: 0
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | Local |
| 1 | Virtual Mirror |
| 2 | Physical Mirror |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

`Virtual Mirror` mode is used when deepflow-agent cannot directly capture the traffic from
the source. For example:
- in the K8s macvlan environment, capture the Pod traffic through the Node NIC
- in the Hyper-V environment, capture the VM traffic through the Hypervisor NIC
- in the ESXi environment, capture traffic through VDS/VSS local SPAN
- in the DPDK environment, capture traffic through DPDK ring buffer

Use `Physical Mirror` mode when deepflow-agent captures traffic through physical
switch mirroring.

<mark>`Physical Mirror` is only supported in the Enterprise Edition.</mark>

### Capture via AF_PACKET {#inputs.cbpf.af_packet}

#### Interface Regex {#inputs.cbpf.af_packet.interface_regex}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.interface_regex`

Upgrade from old version: `tap_interface_regex`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      interface_regex: ^(tap.*|cali.*|veth.*|eth.*|en[osipx].*|lxc.*|lo|[0-9a-f]+_h)$
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 65535] |

**Description**:

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
When it is not configured, it indicates
that network card traffic is not being collected

#### Inner Net Namespace Capture Enabled {#inputs.cbpf.af_packet.inner_interface_capture_enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.inner_interface_capture_enabled`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      inner_interface_capture_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to collect traffic in sub net namespaces.
When enabled, agent will spawn recv engine threads to capture traffic in different namespaces,
causing additional memory consumption for each namespace captured.
The default setting of `inputs.cbpf.af_packet.tunning.ring_blocks` is 128,
which means that the memory consumption will be 128 * 1MB for each namespace.
For example, a node with 20 pods will require 20 * 128 * 1MB = 2.56GB for dispatcher.
Make sure to estimate this memory consumption before enabling this feature.
Enabling `inputs.cbpf.af_packet.tunning.ring_blocks_enabled` and change
`inputs.cbpf.af_packet.tunning.ring_blocks` to reduce memory consumption.

#### Inner Net Namespace Interface Regex {#inputs.cbpf.af_packet.inner_interface_regex}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.inner_interface_regex`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      inner_interface_regex: ^eth\d+$
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 65535] |

**Description**:

Regular expression of NIC name for collecting traffic in sub net namespaces.

#### Bond Interfaces {#inputs.cbpf.af_packet.bond_interfaces}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.bond_interfaces`

Upgrade from old version: `static_config.tap-interface-bond-groups`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      bond_interfaces: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Packets of interfaces in the same group can be aggregated together,
Only effective when `inputs.cbpf.common.capture_mode` is 0.

Example:
```yaml
inputs:
  cbpf:
    af_packet:
      bond_interfaces:
      - slave_interfaces: [eth0, eth1]
      - slave_interfaces: [eth2, eth3]
```

##### Slave Interfaces {#inputs.cbpf.af_packet.bond_interfaces.slave_interfaces}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.bond_interfaces.slave_interfaces`

Upgrade from old version: `static_config.tap-interface-bond-groups.tap-interfaces`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      bond_interfaces:
      - slave_interfaces: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

The slave interfaces of one bond interface.

#### Extra Network Namespace Regex {#inputs.cbpf.af_packet.extra_netns_regex}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.af_packet.extra_netns_regex`

Upgrade from old version: `extra_netns_regex`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      extra_netns_regex: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Packet will be captured in regex matched namespaces besides the default
namespace. NICs captured in extra namespaces are also filtered with
`inputs.cbpf.af_packet.interface_regex`.

Default value `""` means no extra network namespace (default namespace only).

#### Extra BPF Filter {#inputs.cbpf.af_packet.extra_bpf_filter}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.extra_bpf_filter`

Upgrade from old version: `capture_bpf`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      extra_bpf_filter: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 512] |

**Description**:

If not configured, all traffic will be collected. Please
refer to BPF syntax: [https://biot.com/capstats/bpf.html](https://biot.com/capstats/bpf.html)

#### TAP Interfaces {#inputs.cbpf.af_packet.src_interfaces}

**Tags**:

<mark></mark>
<mark>deprecated</mark>

**FQCN**:

`inputs.cbpf.af_packet.src_interfaces`

Upgrade from old version: `static_config.src-interfaces`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      src_interfaces: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

#### VLAN PCP in Physical Mirror Traffic {#inputs.cbpf.af_packet.vlan_pcp_in_physical_mirror_traffic}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.af_packet.vlan_pcp_in_physical_mirror_traffic`

Upgrade from old version: `static_config.mirror-traffic-pcp`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      vlan_pcp_in_physical_mirror_traffic: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 9] |

**Description**:

- When this configuration <= 7 calculate TAP value from vlan tag only if vlan pcp matches this value.
- when this configuration is 8 calculate TAP value from outer vlan tag,
- when this configuration is 9 calculate TAP value from inner vlan tag.

#### BPF Filter Disabled {#inputs.cbpf.af_packet.bpf_filter_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.bpf_filter_disabled`

Upgrade from old version: `static_config.bpf-disabled`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      bpf_filter_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

It is found that there may be bugs in BPF traffic filtering under some
versions of Linux Kernel. After this configuration is enabled, deepflow-agent
will not use the filtering capabilities of BPF, and will filter by itself after
capturing full traffic. Note that this may significantly increase the resource
overhead of deepflow-agent.

#### Skip NPB BPF {#inputs.cbpf.af_packet.skip_npb_bpf}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.skip_npb_bpf`

Upgrade from old version: `static_config.skip-npb-bpf`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      skip_npb_bpf: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

If the NIC on the data plane has ERSPAN tunnel traffic but does not NPB traffic,
enable the switch to collect ERSPAN traffic.

#### Tunning {#inputs.cbpf.af_packet.tunning}

##### Socket Version {#inputs.cbpf.af_packet.tunning.socket_version}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.af_packet.tunning.socket_version`

Upgrade from old version: `capture_socket_type`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        socket_version: 0
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | Adaptive |
| 2 | AF_PACKET V2 |
| 3 | AF_PACKET V3 |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

AF_PACKET socket version in Linux environment.

##### Ring Blocks Config Enabled {#inputs.cbpf.af_packet.tunning.ring_blocks_enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.ring_blocks_enabled`

Upgrade from old version: `static_config.afpacket-blocks-enabled`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        ring_blocks_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When `inputs.cbpf.common.capture_mode` != `Physical Mirror`, you need to explicitly turn on this switch to
configure 'inputs.cbpf.af_packet.tunning.ring_blocks'.

##### Ring Blocks {#inputs.cbpf.af_packet.tunning.ring_blocks}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.ring_blocks`

Upgrade from old version: `static_config.afpacket-blocks`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        ring_blocks: 128
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8, 1000000] |

**Description**:

deepflow-agent will automatically calculate the number of blocks
used by AF_PACKET according to max_memory, which can also be specified
using this configuration item. The size of each block is fixed at 1MB.

##### Packet Fanout Count {#inputs.cbpf.af_packet.tunning.packet_fanout_count}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.packet_fanout_count`

Upgrade from old version: `static_config.local-dispatcher-count`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        packet_fanout_count: 1
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 64] |

**Description**:

The configuration takes effect when `inputs.cbpf.common.capture_mode` is `Local` and `inputs.cbpf.af_packet.extra_netns_regex` is null,
PACKET_FANOUT is to enable load balancing and parallel processing, scaling dispatcher for
better performance of handling network applications. When the `packet_fanout_count`
is greater than 1, multiple dispatcher threads will be launched, consuming more CPU and
memory. Increasing the `packet_fanout_count` helps to reduce the operating system's
software interrupts on multi-core CPU servers.

Attention:
- only valid for `inputs.cbpf.common.capture_mode` = `Local`
- When `self.inputs.cbpf.special_network.dpdk.source` is `eBPF`, this configuration value is forced to be `self.inputs.ebpf.tunning.userspace_worker_threads`

##### Packet Fanout Mode {#inputs.cbpf.af_packet.tunning.packet_fanout_mode}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.packet_fanout_mode`

Upgrade from old version: `static_config.packet-fanout-mode`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        packet_fanout_mode: 0
```

**Enum options**:
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

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

The configuration is a parameter used with the PACKET_FANOUT feature in the Linux
kernel to specify the desired packet distribution algorithm. Refer to:
- [https://github.com/torvalds/linux/blob/afcd48134c58d6af45fb3fdb648f1260b20f2326/include/uapi/linux/if_packet.h#L71](https://github.com/torvalds/linux/blob/afcd48134c58d6af45fb3fdb648f1260b20f2326/include/uapi/linux/if_packet.h#L71)
- [https://www.stackpath.com/blog/bpf-hook-points-part-1/](https://github.com/torvalds/linux/blob/afcd48134c58d6af45fb3fdb648f1260b20f2326/include/uapi/linux/if_packet.h#L71)

##### Interface Promisc Enabled {#inputs.cbpf.af_packet.tunning.interface_promisc_enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.af_packet.tunning.interface_promisc_enabled`

**Default value**:
```yaml
inputs:
  cbpf:
    af_packet:
      tunning:
        interface_promisc_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

The following scenarios require promiscuous mode to be enabled:
- `inputs.cbpf.common.capture_mode` is `Virtual Mirror` or `Physical Mirror`
- `inputs.cbpf.common.capture_mode` is `Local` and traffic to the virtual machine cannot be collected
Note: After the NIC is enabled in promiscuous mode, more traffic will be collected, resulting in lower performance

### Special Network {#inputs.cbpf.special_network}

#### DPDK {#inputs.cbpf.special_network.dpdk}

##### Data Source {#inputs.cbpf.special_network.dpdk.source}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.dpdk.source`

**Default value**:
```yaml
inputs:
  cbpf:
    special_network:
      dpdk:
        source: None
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| None | |
| eBPF | |
| pdump | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Currently, there are two ways to collect DPDK traffic, including:
- pdump: See details [https://dpdk-docs.readthedocs.io/en/latest/prog_guide/multi_proc_support.html](https://dpdk-docs.readthedocs.io/en/latest/prog_guide/multi_proc_support.html)
- eBPF: Use eBPF Uprobe to obtain DPDK traffic, configuration `inputs.ebpf.socket.uprobe.dpdk` is also required.

##### reorder cache window size {#inputs.cbpf.special_network.dpdk.reorder_cache_window_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.special_network.dpdk.reorder_cache_window_size`

**Default value**:
```yaml
inputs:
  cbpf:
    special_network:
      dpdk:
        reorder_cache_window_size: 60ms
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['60ms', '100ms'] |

**Description**:

When `inputs.cbpf.special_network.dpdk.source` is eBPF, the larger the time window will cause the agent to use more memory.

#### Libpcap {#inputs.cbpf.special_network.libpcap}

##### Enabled {#inputs.cbpf.special_network.libpcap.enabled}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.libpcap.enabled`

Upgrade from old version: `static_config.libpcap-enabled`

**Default value**:
```yaml
inputs:
  cbpf:
    special_network:
      libpcap:
        enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Supports running on Windows and Linux, Low performance when using multiple interfaces.
Default to true in Windows, false in Linux.

#### vHost User {#inputs.cbpf.special_network.vhost_user}

##### vHost Socket Path {#inputs.cbpf.special_network.vhost_user.vhost_socket_path}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.vhost_user.vhost_socket_path`

Upgrade from old version: `static_config.vhost-socket-path`

**Default value**:
```yaml
inputs:
  cbpf:
    special_network:
      vhost_user:
        vhost_socket_path: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Supports running on Linux with mirror mode.

#### Physical Switch {#inputs.cbpf.special_network.physical_switch}

##### sFlow Receiving Ports {#inputs.cbpf.special_network.physical_switch.sflow_ports}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.physical_switch.sflow_ports`

Upgrade from old version: `static_config.xflow-collector.sflow-ports`

**Default value**:
```yaml
inputs:
  cbpf:
    special_network:
      physical_switch:
        sflow_ports: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

This feature is only supported by the Enterprise Edition of Trident.
In general, sFlow uses port 6343. Default value `[]` means that no sFlow
data will be collected.

##### NetFlow Receiving Ports {#inputs.cbpf.special_network.physical_switch.netflow_ports}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.special_network.physical_switch.netflow_ports`

Upgrade from old version: `static_config.xflow-collector.netflow-ports`

**Default value**:
```yaml
inputs:
  cbpf:
    special_network:
      physical_switch:
        netflow_ports: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

This feature is only supported by the Enterprise Edition of Trident.
Additionally, only NetFlow v5 is currently supported. In general, NetFlow
uses port 2055. Default value `[]` means that no NetFlow data will be collected.

### Tunning {#inputs.cbpf.tunning}

#### Dispatcher Queue Enabled {#inputs.cbpf.tunning.dispatcher_queue_enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.tunning.dispatcher_queue_enabled`

Upgrade from old version: `static_config.dispatcher-queue`

**Default value**:
```yaml
inputs:
  cbpf:
    tunning:
      dispatcher_queue_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

The configuration takes effect when `inputs.cbpf.common.capture_mode` is `Local` or `Virtual Mirror`,
dispatcher-queue is always true when `inputs.cbpf.common.capture_mode` is `Physical Mirror`.

Available for all recv_engines.

#### Maximum Capture Packet Size {#inputs.cbpf.tunning.max_capture_packet_size}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.tunning.max_capture_packet_size`

Upgrade from old version: `capture_packet_size`

**Default value**:
```yaml
inputs:
  cbpf:
    tunning:
      max_capture_packet_size: 65535
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [128, 65535] |

**Description**:

DPDK environment does not support this configuration.

#### Raw Packet Buffer Block Size {#inputs.cbpf.tunning.raw_packet_buffer_block_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.tunning.raw_packet_buffer_block_size`

Upgrade from old version: `static_config.analyzer-raw-packet-block-size`

**Default value**:
```yaml
inputs:
  cbpf:
    tunning:
      raw_packet_buffer_block_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 16000000] |

**Description**:

In certain modes, raw packets will go through a queue before being processed.
To avoid memory allocation for each packet, a memory block of size
raw_packet_buffer_block_size is allocated for multiple packets.
Larger value will reduce memory allocation for raw packet, but will also
delay memory free.
This configuration is effective for the following `inputs.cbpf.common.capture_mode`:
- analyzer mode
- local mode with `inputs.cbpf.af_packet.inner_interface_capture_enabled` = true
- local mode with `inputs.cbpf.tunning.dispatcher_queue_enabled` = true
- mirror mode with `inputs.cbpf.tunning.dispatcher_queue_enabled` = true

#### Raw Packet Queue Size {#inputs.cbpf.tunning.raw_packet_queue_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.tunning.raw_packet_queue_size`

Upgrade from old version: `static_config.analyzer-queue-size`

**Default value**:
```yaml
inputs:
  cbpf:
    tunning:
      raw_packet_queue_size: 131072
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues (only for `inputs.cbpf.common.capture_mode` = `Physical Mirror`):
- 0.1-bytes-to-parse
- 0.2-packet-to-flowgenerator
- 0.3-packet-to-pipeline

#### Max Capture PPS {#inputs.cbpf.tunning.max_capture_pps}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.tunning.max_capture_pps`

Upgrade from old version: `max_collect_pps`

**Default value**:
```yaml
inputs:
  cbpf:
    tunning:
      max_capture_pps: 1048576
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | pps |
| Range | [1, 10000000] |

**Description**:

Maximum packet rate allowed for collection.

Available for all recv_engines.

### Preprocess {#inputs.cbpf.preprocess}

#### Tunnel Decap Protocols {#inputs.cbpf.preprocess.tunnel_decap_protocols}

**Tags**:

`hot_update`

**FQCN**:

`inputs.cbpf.preprocess.tunnel_decap_protocols`

Upgrade from old version: `decap_type`

**Default value**:
```yaml
inputs:
  cbpf:
    preprocess:
      tunnel_decap_protocols:
      - 1
      - 2
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 1 | VXLAN |
| 2 | IPIP |
| 3 | GRE |
| 4 | Geneve |
| 5 | VXLAN-NSH |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

Decapsulation tunnel protocols, Only the Enterprise Edition supports decap GRE and VXLAN-NSH.

#### Tunnel Trim Protocols {#inputs.cbpf.preprocess.tunnel_trim_protocols}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.cbpf.preprocess.tunnel_trim_protocols`

Upgrade from old version: `static_config.trim-tunnel-types`

**Default value**:
```yaml
inputs:
  cbpf:
    preprocess:
      tunnel_trim_protocols: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| ERSPAN | |
| VXLAN | |
| TEB | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Whether to remove the tunnel header in mirrored traffic.
Only the Enterprise Edition supports decap ERSPAN and TEB.

#### Packet Segmentation Reassembly Ports {#inputs.cbpf.preprocess.packet_segmentation_reassembly}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.preprocess.packet_segmentation_reassembly`

Upgrade from old version: `static_config.packet-segmentation-reassembly`

**Default value**:
```yaml
inputs:
  cbpf:
    preprocess:
      packet_segmentation_reassembly: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

For the specified ports, consecutive TCP packets will be aggregated together for application log parsing.

### Physical Mirror Traffic {#inputs.cbpf.physical_mirror}

#### Default Capture Network Type {#inputs.cbpf.physical_mirror.default_capture_network_type}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.physical_mirror.default_capture_network_type`

Upgrade from old version: `static_config.default-tap-type`

**Default value**:
```yaml
inputs:
  cbpf:
    physical_mirror:
      default_capture_network_type: 3
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 3 | Cloud Network |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

deepflow-agent will mark the TAP (Traffic Access Point) location
according to the outer vlan tag in the mirrored traffic of the physical
switch. When the vlan tag has no corresponding TAP value, or the vlan
pcp does not match the `inputs.cbpf.af_packet.vlan_pcp_in_physical_mirror_traffic`, it will assign the TAP value.
This configuration item. Default value `3` means Cloud Network.

#### Packet Dedup Disabled {#inputs.cbpf.physical_mirror.packet_dedup_disabled}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.physical_mirror.packet_dedup_disabled`

Upgrade from old version: `static_config.analyzer-dedup-disabled`

**Default value**:
```yaml
inputs:
  cbpf:
    physical_mirror:
      packet_dedup_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to enable mirror traffic deduplication when `inputs.cbpf.common.capture_mode` = `Physical Mirror`.

#### Gateway Traffic of Private Cloud {#inputs.cbpf.physical_mirror.private_cloud_gateway_traffic}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.cbpf.physical_mirror.private_cloud_gateway_traffic`

Upgrade from old version: `static_config.cloud-gateway-traffic`

**Default value**:
```yaml
inputs:
  cbpf:
    physical_mirror:
      private_cloud_gateway_traffic: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether it is the mirrored traffic of NFVGW (cloud gateway) when `inputs.cbpf.common.capture_mode` = `Physical Mirror`.

## eBPF {#inputs.ebpf}

### Disabled {#inputs.ebpf.disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.disabled`

Upgrade from old version: `static_config.ebpf.disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to enable eBPF features.

### Socket {#inputs.ebpf.socket}

#### Uprobe {#inputs.ebpf.socket.uprobe}

##### Golang {#inputs.ebpf.socket.uprobe.golang}

###### Enabled {#inputs.ebpf.socket.uprobe.golang.enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.golang.enabled`

Upgrade from old version: `static_config.ebpf.uprobe-golang-trace-enabled, static_config.ebpf.uprobe-process-name-regexs.golang`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        golang:
          enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether golang process enables HTTP2/HTTPS protocol data collection
and auto-tracing. go auto-tracing also dependent go-tracing-timeout.

Note: When enabling this feature, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `ebpf.socket.uprobe.golang` must be included in `inputs.proc.process_matcher.[*].enabled_features`.

###### Tracing Timeout {#inputs.ebpf.socket.uprobe.golang.tracing_timeout}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.golang.tracing_timeout`

Upgrade from old version: `static_config.ebpf.go-tracing-timeout`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        golang:
          tracing_timeout: 120s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1d'] |

**Description**:

The expected maximum time interval between the server receiving the request and returning
the response, If the value is '0ns', this feature is disabled. Tracing only considers the
thread number.

##### TLS {#inputs.ebpf.socket.uprobe.tls}

###### Enabled {#inputs.ebpf.socket.uprobe.tls.enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.tls.enabled`

Upgrade from old version: `static_config.ebpf.uprobe-openssl-trace-enabled, static_config.ebpf.uprobe-process-name-regexs.openssl`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        tls:
          enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether the process that uses the openssl library to enable HTTPS protocol data collection.

One can use the following method to determine whether an application process can use
`Uprobe hook openssl library` to access encrypted data:
- Use the command `cat /proc/<PID>/maps | grep "libssl.so"` to check if it contains
  information about openssl. If it does, it indicates that this process is using the
  openssl library.
- If "libssl.so" is not found above, it may indicate that the program
  is statically linked with OpenSSL. In that case, you can verify it by:
  running the command `sudo nm /proc/<PID>/exe | grep SSL_write`.
  If the output contains symbols such as `0000000000502ac0 T SSL_write`,
  it means the process is using a statically linked OpenSSL library.

After enabled, deepflow-agent will retrieve process information that
matches the regular expression, hooking the corresponding encryption/decryption
interfaces of the openssl library. In the logs, you will encounter a message similar
to the following:
```
[eBPF] INFO openssl uprobe, pid:1005, path:/proc/1005/root/usr/lib64/libssl.so.1.0.2k
OR
[eBPF] INFO openssl uprobe, pid:28890, path:/proc/28890/root/usr/sbin/nginx
```

Note: When this feature is enabled, Envoy mTLS traffic can be automatically traced.
For non-Envoy traffic, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `ebpf.socket.uprobe.tls` must be included in `inputs.proc.process_matcher.[*].enabled_features`.

##### DPDK {#inputs.ebpf.socket.uprobe.dpdk}

###### DPDK Application Command Name {#inputs.ebpf.socket.uprobe.dpdk.command}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.dpdk.command`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        dpdk:
          command: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Set the command name of the DPDK application, eBPF will automatically
locate and trace packets for data collection.

Example: In the command line `/usr/bin/mydpdk`, it can be set as `command: mydpdk`, and set `inputs.cbpf.special_network.dpdk.source = eBPF`

In scenarios where DPDK acts as the vhost-user backend, data exchange between the virtual machine and the DPDK
application occurs through virtqueues (vrings). eBPF can automatically hook into the vring interface without
requiring any modifications to DPDK or the virtual machine, enabling packet capture and traffic observability
with zero additional configuration. In contrast, capturing packets on physical NICs requires explicit configuration
of the corresponding DPDK driver interfaces.

###### DPDK Application RX Hooks Configuration {#inputs.ebpf.socket.uprobe.dpdk.rx_hooks}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.dpdk.rx_hooks`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        dpdk:
          rx_hooks: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Fill in the appropriate packet reception hook point according to the actual network card driver.
You can use the command 'lspci -vmmk' to find the network card driver type. For example:
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
In the example above, "Driver: igb_uio" indicates a DPDK-managed device (other options include
"vfio-pci" and "uio_pci_generic", which are also managed by DPDK). The actual driver is 'i40e'
(derived from 'Module: i40e').

You can use the sustainable profiling feature provided by DeepFlow to perform function profiling
on the DPDK application and check the specific interface names. Alternatively, you can run the
`perf` command on the node where the agent is located:
`perf record -F97 -a -g -p <DPDK application PID> -- sleep 30`
and then use
`perf script | grep -E 'recv|xmit|rx|tx' | grep <drive_name>` (`drive_name` may be `ixgbe/i40e/mlx5`)
to confirm the driver interfaces.

Below are some common interface names for different drivers, for reference only:
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
         - tx: virtio_xmit_pkts_packed, virtio_xmit_pkts
     - VMXNET3 Driver:
       - vmxnet3: Supports VMware's VMXNET3 virtual NICs.
         - rx: vmxnet3_recv_pkts
         - tx: vmxnet3_xmit_pkts

Example: `rx_hooks: [ixgbe_recv_pkts, i40e_recv_pkts, virtio_recv_pkts, virtio_recv_mergeable_pkts]`

Note: When using the burst mode of the current DPDK driver interface to send and receive packets,
the number of eBPF instructions is limited to 4096 in older Linux kernels (below Linux 5.2). As a
result, during DPDK packet capture, only a maximum of 16 packets can be captured. For Linux kernels
5.2 and above, up to 32 packets can be captured (this is typically the default value for DPDK
burst mode). For kernels older than Linux 5.2, packet loss may occur (if the burst size exceeds 16).

###### DPDK Application TX Hooks Configuration {#inputs.ebpf.socket.uprobe.dpdk.tx_hooks}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.uprobe.dpdk.tx_hooks`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      uprobe:
        dpdk:
          tx_hooks: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Specify the appropriate packet transmission hook point according to the actual network card driver.
To obtain the driver method and configure the transmission hook point, as well as precautions，refer
to the description of `inputs.ebpf.socket.uprobe.dpdk.rx_hooks`.

Example: `tx_hooks: [i40e_xmit_pkts, virtio_xmit_pkts_packed, virtio_xmit_pkts]`

#### Kprobe {#inputs.ebpf.socket.kprobe}

##### kprobe disabled {#inputs.ebpf.socket.kprobe.disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When set to true, kprobe will be disabled.

##### Unix Socket Enabled {#inputs.ebpf.socket.kprobe.enable_unix_socket}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.enable_unix_socket`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        enable_unix_socket: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When set to true, enable tracing of Unix domain sockets.

##### Blacklist {#inputs.ebpf.socket.kprobe.blacklist}

###### Port Numbers {#inputs.ebpf.socket.kprobe.blacklist.ports}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.blacklist.ports`

Upgrade from old version: `static_config.ebpf.kprobe-blacklist.port-list`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        blacklist:
          ports: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

TCP&UDP Port Blacklist, Priority higher than kprobe-whitelist.

Example: `ports: 80,1000-2000`

##### Whitelist {#inputs.ebpf.socket.kprobe.whitelist}

###### Port Numbers {#inputs.ebpf.socket.kprobe.whitelist.ports}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.kprobe.whitelist.ports`

Upgrade from old version: `static_config.ebpf.kprobe-whitelist.port-list`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      kprobe:
        whitelist:
          ports: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

TCP&UDP Port Whitelist, Priority lower than kprobe-blacklist.
Use kprobe to collect data on ports that are not in the blacklist or whitelist.

Example: `ports: 80,1000-2000`

#### Tunning {#inputs.ebpf.socket.tunning}

##### Max Capture Rate {#inputs.ebpf.socket.tunning.max_capture_rate}

**Tags**:

`hot_update`

**FQCN**:

`inputs.ebpf.socket.tunning.max_capture_rate`

Upgrade from old version: `static_config.ebpf.global-ebpf-pps-threshold`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        max_capture_rate: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Per Second |
| Range | [0, 64000000] |

**Description**:

Default value `0` means no limitation.

##### Syscall_trace_id Disabled {#inputs.ebpf.socket.tunning.syscall_trace_id_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.tunning.syscall_trace_id_disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        syscall_trace_id_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When the trace_id is injected into all requests, the computation logic for all
syscall_trace_id can be turned off. This will significantly reduce the impact of the
eBPF hook on the CPU consumption of the application process.

##### Disable Pre-allocating Memory {#inputs.ebpf.socket.tunning.map_prealloc_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.tunning.map_prealloc_disabled`

Upgrade from old version: `static_config.ebpf.map-prealloc-disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        map_prealloc_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When full map preallocation is too expensive, set this configuration to `true` will
prevent memory pre-allocation during map definition, but it may result in some performance
degradation. This configuration only applies to maps of type 'BPF_MAP_TYPE_HASH'.
Currently applicable to socket trace and uprobe Golang/OpenSSL trace functionalities.
Disabling memory preallocation will approximately reduce memory usage by 45MB.

##### Enable the fentry/fexit feature {#inputs.ebpf.socket.tunning.fentry_enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.socket.tunning.fentry_enabled`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      tunning:
        fentry_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Explanation of Using fentry/fexit Features
- Compared to traditional kprobes, fentry and fexit programs offer higher performance and
  availability, providing approximately 5%-10% performance improvement.
- Some Linux kernels do not fully support this feature, which may lead to kernel bugs and
  node crashes. Known bug fixes include:
  - Bug fix for TencentOS Linux kernel 5.4.119
    [https://github.com/torvalds/linux/commit/c3d6324f841bab2403be6419986e2b1d1068d423](https://github.com/torvalds/linux/commit/c3d6324f841bab2403be6419986e2b1d1068d423)
  - Bug fix for Alibaba Cloud Linux kernel 5.10.23
    [https://github.com/gregkh/linux/commit/e21d2b92354b3cd25dd774ebb0f0e52ff04a7861](https://github.com/gregkh/linux/commit/e21d2b92354b3cd25dd774ebb0f0e52ff04a7861)
- Kernel recommendation: To enable the fentry/fexit feature, it is recommended to use Linux
  kernel 5.10.28 or later to ensure stability and performance.

#### Preprocess {#inputs.ebpf.socket.preprocess}

##### OOOR Cache Size {#inputs.ebpf.socket.preprocess.out_of_order_reassembly_cache_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.preprocess.out_of_order_reassembly_cache_size`

Upgrade from old version: `static_config.ebpf.syscall-out-of-order-cache-size`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      preprocess:
        out_of_order_reassembly_cache_size: 16
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8, 1024] |

**Description**:

OOOR: Out Of Order Reassembly

When `out_of_order_reassembly_protocols` is enabled, up to `out_of_order_reassembly_cache_size`
eBPF socket events (each event consuming up to `processors.request_log.tunning.payload_truncation` bytes) will be cached
in each TCP/UDP flow to prevent out-of-order events from impacting application protocol
parsing. Since eBPF socket events are sent to user space in batches, out-of-order scenarios
mainly occur when requests and responses within a single session are processed by different
CPUs, causing the response to reach user space before the request.

##### OOOR Protocols {#inputs.ebpf.socket.preprocess.out_of_order_reassembly_protocols}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.preprocess.out_of_order_reassembly_protocols`

Upgrade from old version: `static_config.ebpf.syscall-out-of-order-reassembly`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      preprocess:
        out_of_order_reassembly_protocols: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

OOOR: Out Of Order Reassembly

When this capability is enabled for a specific application protocol, the agent will add
out-of-order-reassembly processing for it. Note that the agent will consume more memory
in this case, so please adjust the syscall-out-of-order-cache-size accordingly and monitor
the agent's memory usage.

Supported protocols: [https://www.deepflow.io/docs/features/l7-protocols/overview/](https://www.deepflow.io/docs/features/l7-protocols/overview/)

Attention: configuring `HTTP2` or `gRPC` will enable both protocols.

##### SR Protocols {#inputs.ebpf.socket.preprocess.segmentation_reassembly_protocols}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.socket.preprocess.segmentation_reassembly_protocols`

Upgrade from old version: `static_config.ebpf.syscall-segmentation-reassembly`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      preprocess:
        segmentation_reassembly_protocols: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

SR: Segmentation Reassembly

When this capability is enabled for a specific application protocol, the agent will add
segmentation-reassembly processing to merge application protocol content spread across
multiple syscalls before parsing it. This enhances the success rate of application
protocol parsing. Note that `out_of_order_reassembly_protocols` must also be enabled for
this feature to be effective.
Supported protocols: [https://www.deepflow.io/docs/features/l7-protocols/overview/](https://www.deepflow.io/docs/features/l7-protocols/overview/)
Attention: configuring `HTTP2` or `gRPC` will enable both protocols.

### TCP Option Trace {#inputs.ebpf.socket.sock_ops.tcp_option_trace}

#### Enabled {#inputs.ebpf.socket.sock_ops.tcp_option_trace.enabled}

**Tags**:

`hot_update`

**FQCN**:

`inputs.ebpf.socket.sock_ops.tcp_option_trace.enabled`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      sock_ops:
        tcp_option_trace:
          enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to enable the tcp-option tracing SockOps program, which injects DeepFlow metadata (for example, process PID) into a custom TCP option for eligible connections.

Note: This feature requires cgroup v2 (unified hierarchy). On hosts using cgroup v1 the SockOps program will fail to attach and the agent will log a warning.

Limitation: PID tracking relies on the per-CPU syscall map defined in `agent/src/ebpf/user/extended/bpf/tcp_option_tracing.bpf.c`. Under CPU congestion, TCP softirqs may run on a different CPU than the userspace thread and the injected metadata can be missing or stale.

#### PID Injection Window {#inputs.ebpf.socket.sock_ops.tcp_option_trace.sampling_window_bytes}

**Tags**:

`hot_update`

**FQCN**:

`inputs.ebpf.socket.sock_ops.tcp_option_trace.sampling_window_bytes`

**Default value**:
```yaml
inputs:
  ebpf:
    socket:
      sock_ops:
        tcp_option_trace:
          sampling_window_bytes: 16384
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Bytes |
| Range | [0, 1048576] |

**Description**:

Minimum number of TCP payload bytes between PID injections. Default 16KB matches the legacy behavior; smaller windows increase frequency, larger windows decrease it. Set to `0` to disable sampling and inject on every eligible packet.

### File {#inputs.ebpf.file}

#### IO Event {#inputs.ebpf.file.io_event}

##### Collect Mode {#inputs.ebpf.file.io_event.collect_mode}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.file.io_event.collect_mode`

Upgrade from old version: `static_config.ebpf.io-event-collect-mode`

**Default value**:
```yaml
inputs:
  ebpf:
    file:
      io_event:
        collect_mode: 1
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | Disabled |
| 1 | Request Life Cycle |
| 2 | All |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

Collection modes:
- Disabled: Indicates that no IO events are collected.
- Request Life Cycle: Indicates that only IO events within the request life cycle are collected.
- All: Indicates that all IO events are collected.

Note:
- To obtain the full file path, we need to combine it with the process's mount information. However,
  some processes exit quickly after completing their tasks. When we attempt to process the file I/O
  data generated by such processes, the corresponding /proc/[pid]/mountinfo entry may no longer be
  available, resulting in incomplete paths (missing mount points). For processes with a lifetime
  shorter than 50 ms, the file path may lack mount point information. This issue does not occur with
  long-running processes.

##### Minimal Duration {#inputs.ebpf.file.io_event.minimal_duration}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.file.io_event.minimal_duration`

Upgrade from old version: `static_config.ebpf.io-event-minimal-duration`

**Default value**:
```yaml
inputs:
  ebpf:
    file:
      io_event:
        minimal_duration: 1ms
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1ns', '1s'] |

**Description**:

Only collect IO events with delay exceeding this threshold.

##### Virtual File Collection Enabled {#inputs.ebpf.file.io_event.enable_virtual_file_collect}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.file.io_event.enable_virtual_file_collect`

**Default value**:
```yaml
inputs:
  ebpf:
    file:
      io_event:
        enable_virtual_file_collect: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When set to true, the agent will collect file I/O events generated on
virtual file systems (such as /proc, /sys, /run, and other kernel
pseudo file systems).
When set to false, the agent will not collect file I/O events from
virtual file systems.

### Profile {#inputs.ebpf.profile}

#### Unwinding {#inputs.ebpf.profile.unwinding}

##### DWARF unwinding disabled {#inputs.ebpf.profile.unwinding.dwarf_disabled}

**Tags**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_disabled`

Upgrade from old version: `static_config.ebpf.dwarf-disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_disabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

The default setting is `true`, agent will use frame pointer based unwinding for
all processes. If a process does not contain frame pointers, the stack cannot be
displayed correctly.
Setting it to `false` will enable DWARF based stack unwinding for all processes that
do not contain frame pointers. Agent uses a heuristic algorithm to determine whether
the process being analyzed contains frame pointers.
Additionally, setting `dwarf_regex` to force DWARF based stack unwinding for certain
processes.

##### DWARF unwinding process matching regular expression {#inputs.ebpf.profile.unwinding.dwarf_regex}

**Tags**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_regex`

Upgrade from old version: `static_config.ebpf.dwarf-regex`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_regex: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

If set to empty, agennt will use a heuristic algorithm to determine whether the process
being analyzed contains frame pointers, and will use DWARF based stack unwinding for
processes that do not contain frame pointers.
If set to a valid regular expression, agent will no longer infer whether a process contains
frame pointers but will instead use the provided regular expression to match process names,
applying DWARF based stack unwinding only to the matching processes.

##### DWARF unwinding process map size {#inputs.ebpf.profile.unwinding.dwarf_process_map_size}

**Tags**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_process_map_size`

Upgrade from old version: `static_config.ebpf.dwarf-process-map-size`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_process_map_size: 1024
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 131072] |

**Description**:

Each process using DWARF unwind has an entry in this map, relating process id to DWARF unwind entries.
The size of each one of these entries is arount 8K, the default setting will allocate around 8M kernel memory.
This is a hash map, so size can be lower than max process id.
The configuration is only effective if DWARF is enabled.

##### DWARF unwinding shard map size {#inputs.ebpf.profile.unwinding.dwarf_shard_map_size}

**Tags**:

`hot_update`

**FQCN**:

`inputs.ebpf.profile.unwinding.dwarf_shard_map_size`

Upgrade from old version: `static_config.ebpf.dwarf-shard-map-size`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      unwinding:
        dwarf_shard_map_size: 128
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 4096] |

**Description**:

The number of unwind entry shards for DWARF unwinding.
The size of each one of these entries is 1M, the default setting will allocate around 128M kernel memory.
The configuration is only effective if DWARF is enabled.

#### On-CPU {#inputs.ebpf.profile.on_cpu}

##### Disabled {#inputs.ebpf.profile.on_cpu.disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.on_cpu.disabled`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      on_cpu:
        disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

eBPF On-CPU profile switch.

Note: When enabling this feature, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `ebpf.profile.on_cpu` must be included in `inputs.proc.process_matcher.[*].enabled_features`.

##### Sampling Frequency {#inputs.ebpf.profile.on_cpu.sampling_frequency}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.on_cpu.sampling_frequency`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.frequency`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      on_cpu:
        sampling_frequency: 99
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 1000] |

**Description**:

eBPF On-CPU profile sampling frequency.

##### Aggregate by CPU {#inputs.ebpf.profile.on_cpu.aggregate_by_cpu}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.on_cpu.aggregate_by_cpu`

Upgrade from old version: `static_config.ebpf.on-cpu-profile.cpu`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      on_cpu:
        aggregate_by_cpu: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to obtain the value of CPUID and decide whether to participate in aggregation.
- `true`: Obtain the value of CPUID and will be included in the aggregation of stack
  trace data.
- `false`: It will not be included in the aggregation. Any other value is considered
  invalid, the CPU value for stack trace data reporting is a special value
  `CPU_INVALID: 0xfff` used to indicate that it is an invalid value.

#### Off-CPU {#inputs.ebpf.profile.off_cpu}

##### Disabled {#inputs.ebpf.profile.off_cpu.disabled}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.off_cpu.disabled`

Upgrade from old version: `static_config.ebpf.off-cpu-profile.disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      off_cpu:
        disabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

eBPF Off-CPU profile switch.

Note: When enabling this feature, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `ebpf.profile.off_cpu` must be included in `inputs.proc.process_matcher.[*].enabled_features`.

##### Aggregate by CPU {#inputs.ebpf.profile.off_cpu.aggregate_by_cpu}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.off_cpu.aggregate_by_cpu`

Upgrade from old version: `static_config.ebpf.off-cpu-profile.cpu`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      off_cpu:
        aggregate_by_cpu: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to obtain the value of CPUID and decide whether to participate in aggregation.
- `true`: Obtain the value of CPUID and will be included in the aggregation of stack
  trace data.
- `false`: It will not be included in the aggregation. Any other value is considered
  invalid, the CPU value for stack trace data reporting is a special value
  `CPU_INVALID: 0xfff` used to indicate that it is an invalid value.

##### Minimum Blocking Time {#inputs.ebpf.profile.off_cpu.min_blocking_time}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.off_cpu.min_blocking_time`

Upgrade from old version: `static_config.ebpf.off-cpu-profile.minblock`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      off_cpu:
        min_blocking_time: 50us
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1h'] |

**Description**:

If set to '0ns', there will be no minimum value limitation. Scheduler events are still
high-frequency events, as their rate may exceed 1 million events per second, so
caution should still be exercised.

If overhead remains an issue, you can configure the 'minblock' tunable parameter here.
If the off-CPU time is less than the value configured in this item, the data will be
discarded. If your goal is to trace longer blocking events, increasing this parameter
can filter out shorter blocking events, further reducing overhead. Additionally, we
will not collect events with a blocking time exceeding 1 hour.

#### Memory {#inputs.ebpf.profile.memory}

##### Disabled {#inputs.ebpf.profile.memory.disabled}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.disabled`

Upgrade from old version: `static_config.ebpf.memory-profile.disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        disabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

eBPF memory profile switch.

Note: When enabling this feature, the specific process list must also be specified in `inputs.proc.process_matcher`,
i.e., `ebpf.profile.memory` must be included in `inputs.proc.process_matcher.[*].enabled_features`.

##### Memory profile report interval {#inputs.ebpf.profile.memory.report_interval}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.report_interval`

Upgrade from old version: `static_config.ebpf.memory-profile.report-interval`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        report_interval: 10s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '60s'] |

**Description**:

The interval at which deepflow-agent aggregates and reports memory profile data.

##### LRU length for process allocated addresses {#inputs.ebpf.profile.memory.allocated_addresses_lru_len}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.allocated_addresses_lru_len`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        allocated_addresses_lru_len: 131072
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 4194704] |

**Description**:

Agent uses LRU cache to record process allocated addresses to avoid uncontrolled
memory usage. Each record in this LRU is about 80B.

##### Sort length {#inputs.ebpf.profile.memory.sort_length}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.sort_length`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        sort_length: 16384
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 65536] |

**Description**:

In order to match mallocs and frees, memory profiler will sort data by timestamp before processing.
This parameter is the length of the sorted array.
When configuring this option, first adjust the `sort_interval` parameter according to the instructions,
and then refer to the agent performance statistics in `deepflow_agent_ebpf_memory_profiler`
`dequeued_by_length` and `dequeued_by_interval` metrics, appropriately reduce this parameter
while ensuring that the former is several times smaller than the latter.

##### Sort interval {#inputs.ebpf.profile.memory.sort_interval}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.sort_interval`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        sort_interval: 1500ms
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1ns', '10s'] |

**Description**:

In order to match mallocs and frees, memory profiler will sort data by timestamp before processing.
This parameter controls the max span of interval between the first and last item in the sorted array.
Refer to agent performance statistics in `deepflow_agent_ebpf_memory_profiler`,
making `time_backtracked` to 0. Configurion `sort_length` may also need to be increased.

##### Queue Size {#inputs.ebpf.profile.memory.queue_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`inputs.ebpf.profile.memory.queue_size`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      memory:
        queue_size: 32768
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [4096, 64000000] |

**Description**:

Memory profiler inner queue size.
Refer to agent performance statistics in `deepflow_agent_ebpf_memory_profiler`,
making `overwritten` to 0 and `pending` not exceeding this configuration.

#### Preprocess {#inputs.ebpf.profile.preprocess}

##### Stack Compression {#inputs.ebpf.profile.preprocess.stack_compression}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.preprocess.stack_compression`

Upgrade from old version: `static_config.ebpf.preprocess.stack-compression`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      preprocess:
        stack_compression: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Compress the call stack before sending data. Compression can effectively reduce the agent's
memory usage, data transmission bandwidth consumption, and ingester's CPU overhead. However,
it also increases the CPU usage of the agent. Tests have shown that compressing the on-cpu
function call stack of the deepflow-agent can reduce bandwidth consumption by `x` times, but
it will result in an additional `y%` CPU usage for the agent.

#### Language-specific Profiling {#inputs.ebpf.profile.languages}

Control which interpreter languages to profile. Disabling unused languages can save ~5-6 MB memory per language.
Total memory: ~17-20 MB (all enabled), ~6.1 MB (Python only), ~5.2 MB (PHP only), ~6.4 MB (Node.js only).

##### Python profiling disabled {#inputs.ebpf.profile.languages.python_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.languages.python_disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      languages:
        python_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Disable Python interpreter profiling. When disabled, Python process stack traces will not be collected,
saving approximately 6.1 MB of kernel memory (python_tstate_addr_map, python_unwind_info_map, python_offsets_map).

##### PHP profiling disabled {#inputs.ebpf.profile.languages.php_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.languages.php_disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      languages:
        php_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Disable PHP interpreter profiling. When disabled, PHP process stack traces will not be collected,
saving approximately 5.2 MB of kernel memory (php_unwind_info_map, php_offsets_map).

##### Node.js profiling disabled {#inputs.ebpf.profile.languages.nodejs_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.profile.languages.nodejs_disabled`

**Default value**:
```yaml
inputs:
  ebpf:
    profile:
      languages:
        nodejs_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Disable Node.js (V8) interpreter profiling. When disabled, Node.js process stack traces will not be collected,
saving approximately 6.4 MB of kernel memory (v8_unwind_info_map).

### Tunning {#inputs.ebpf.tunning}

#### Collector Queue Size {#inputs.ebpf.tunning.collector_queue_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.collector_queue_size`

Upgrade from old version: `static_config.ebpf-collector-queue-size`

**Default value**:
```yaml
inputs:
  ebpf:
    tunning:
      collector_queue_size: 65535
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [4096, 64000000] |

**Description**:

The length of the following queues:
- 0-ebpf-to-ebpf-collector
- 1-proc-event-to-sender
- 1-profile-to-sender

#### Userspace Worker Threads {#inputs.ebpf.tunning.userspace_worker_threads}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.userspace_worker_threads`

Upgrade from old version: `static_config.ebpf.thread-num`

**Default value**:
```yaml
inputs:
  ebpf:
    tunning:
      userspace_worker_threads: 1
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 1024] |

**Description**:

The number of worker threads refers to how many threads participate
in data processing in user-space. The actual maximal value is the number
of CPU logical cores on the host.

#### Perf Pages Count {#inputs.ebpf.tunning.perf_pages_count}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.perf_pages_count`

Upgrade from old version: `static_config.ebpf.perf-pages-count`

**Default value**:
```yaml
inputs:
  ebpf:
    tunning:
      perf_pages_count: 128
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [32, 8192] |

**Description**:

The number of page occupied by the shared memory of the kernel. The
value is `2^n (5 <= n <= 13)`. Used for perf data transfer. If the
value is between `2^n` and `2^(n+1)`, it will be automatically adjusted
by the ebpf configurator to the minimum value `2^n`.
The page size is 4 KB.

#### Kernel Ring Size {#inputs.ebpf.tunning.kernel_ring_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.kernel_ring_size`

Upgrade from old version: `static_config.ebpf.ring-size`

**Default value**:
```yaml
inputs:
  ebpf:
    tunning:
      kernel_ring_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8192, 131072] |

**Description**:

The size of the ring cache queue, The value is `2^n (13 <= n <= 17)`.
If the value is between `2^n` and `2^(n+1)`, it will be automatically
adjusted by the ebpf configurator to the minimum value `2^n`.

#### Maximum Socket Entries {#inputs.ebpf.tunning.max_socket_entries}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.max_socket_entries`

Upgrade from old version: `static_config.ebpf.max-socket-entries`

**Default value**:
```yaml
inputs:
  ebpf:
    tunning:
      max_socket_entries: 131072
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [10000, 2000000] |

**Description**:

Set the maximum value of hash table entries for socket tracking, depending
on the number of concurrent requests in the actual scenario

#### Socket Map Reclaim Threshold {#inputs.ebpf.tunning.socket_map_reclaim_threshold}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.socket_map_reclaim_threshold`

Upgrade from old version: `static_config.ebpf.socket-map-max-reclaim`

**Default value**:
```yaml
inputs:
  ebpf:
    tunning:
      socket_map_reclaim_threshold: 120000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [8000, 2000000] |

**Description**:

The threshold for cleaning socket map table entries.

#### Maximum Trace Entries {#inputs.ebpf.tunning.max_trace_entries}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.ebpf.tunning.max_trace_entries`

Upgrade from old version: `static_config.ebpf.max-trace-entries`

**Default value**:
```yaml
inputs:
  ebpf:
    tunning:
      max_trace_entries: 131072
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [10000, 2000000] |

**Description**:

Set the maximum value of hash table entries for thread/coroutine tracking sessions.

## Resources {#inputs.resources}

### Push Interval {#inputs.resources.push_interval}

**Tags**:

`hot_update`

**FQCN**:

`inputs.resources.push_interval`

Upgrade from old version: `platform_sync_interval`

**Default value**:
```yaml
inputs:
  resources:
    push_interval: 10s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '3600s'] |

**Description**:

The interval at which deepflow-agent actively reports resource information
to deepflow-server.

### Workload Resource Sync Enabled {#inputs.resources.workload_resource_sync_enabled}

**Tags**:

`hot_update`

**FQCN**:

`inputs.resources.workload_resource_sync_enabled`

**Default value**:
```yaml
inputs:
  resources:
    workload_resource_sync_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When enabled, deepflow-server will abstract VM based on the runtime
environment information reported by deepflow-agent.

### Collect Private Cloud Resource {#inputs.resources.private_cloud}

#### Hypervisor Resource Enabled {#inputs.resources.private_cloud.hypervisor_resource_enabled}

**Tags**:

`hot_update`

**FQCN**:

`inputs.resources.private_cloud.hypervisor_resource_enabled`

Upgrade from old version: `platform_enabled`

**Default value**:
```yaml
inputs:
  resources:
    private_cloud:
      hypervisor_resource_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When enabled, deepflow-agent will automatically synchronize virtual
machine and network information on KVM or Linux Host to deepflow-server.
Information collected includes:
- raw_all_vm_xml
- raw_vm_states
- raw_ovs_interfaces
- raw_ovs_ports
- raw_brctl_show
- raw_vlan_config

#### VM MAC Source {#inputs.resources.private_cloud.vm_mac_source}

**Tags**:

`hot_update`

**FQCN**:

`inputs.resources.private_cloud.vm_mac_source`

Upgrade from old version: `if_mac_source`

**Default value**:
```yaml
inputs:
  resources:
    private_cloud:
      vm_mac_source: 0
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | Interface MAC Address |
| 1 | Interface Name |
| 2 | Qemu XML File |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

How to extract the real MAC address of the virtual machine when the
agent runs on the KVM host.

Explanation of the options:
- Interface MAC Address: extracted from tap interface MAC address
- Interface Name: extracted from tap interface name
- Qemu XML File: extracted from the XML file of the virtual machine

#### VM XML Directory {#inputs.resources.private_cloud.vm_xml_directory}

**Tags**:

`hot_update`

**FQCN**:

`inputs.resources.private_cloud.vm_xml_directory`

Upgrade from old version: `vm_xml_path`

**Default value**:
```yaml
inputs:
  resources:
    private_cloud:
      vm_xml_directory: /etc/libvirt/qemu/
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 100] |

**Description**:

VM XML file directory.

#### VM MAC Mapping Script {#inputs.resources.private_cloud.vm_mac_mapping_script}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.private_cloud.vm_mac_mapping_script`

Upgrade from old version: `static_config.tap-mac-script`

**Default value**:
```yaml
inputs:
  resources:
    private_cloud:
      vm_mac_mapping_script: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |
| Range | [0, 100] |

**Description**:

The MAC address mapping relationship of TAP NIC in complex environment can be
constructed by writing a script. The following conditions must be met to use this
script:
1. if_mac_source = 2
2. tap_mode = 0
3. The name of the TAP NIC is the same as in the virtual machine XML file
4. The format of the script output is as follows:
   - tap2d283dfe,11:22:33:44:55:66
   - tap2d283223,aa:bb:cc:dd:ee:ff

### Collect K8s Resource {#inputs.resources.kubernetes}

#### K8s Namespace {#inputs.resources.kubernetes.kubernetes_namespace}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.kubernetes_namespace`

Upgrade from old version: `static_config.kubernetes-namespace`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      kubernetes_namespace: null
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Specify the namespace for agent to query K8s resources.

#### K8s API Resources {#inputs.resources.kubernetes.api_resources}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources`

Upgrade from old version: `static_config.kubernetes-resources`

**Default value**:
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

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Specify kubernetes resources to watch.

The schematics of entries in list is:
{
    name: string
    group: string
    version: string
    disabled: bool
    field_selector: string
}

Agent will watch the following resources by default:
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

##### Name {#inputs.resources.kubernetes.api_resources.name}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.name`

Upgrade from old version: `static_config.kubernetes-resources.name`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - name: ''
```

**Enum options**:
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

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

K8s API resource name.

##### Group {#inputs.resources.kubernetes.api_resources.group}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.group`

Upgrade from old version: `static_config.kubernetes-resources.group`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - group: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

K8s API resource group.

##### Version {#inputs.resources.kubernetes.api_resources.version}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.version`

Upgrade from old version: `static_config.kubernetes-resources.version`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - version: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

K8s API version.

##### Disabled {#inputs.resources.kubernetes.api_resources.disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.disabled`

Upgrade from old version: `static_config.kubernetes-resources.disabled`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

K8s API resource disabled.

##### Field Selector {#inputs.resources.kubernetes.api_resources.field_selector}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_resources.field_selector`

Upgrade from old version: `static_config.kubernetes-resources.field-selector`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      api_resources:
      - field_selector: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

K8s API resource field selector.

#### K8s API List Page Size {#inputs.resources.kubernetes.api_list_page_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_list_page_size`

Upgrade from old version: `static_config.kubernetes-api-list-limit`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      api_list_page_size: 1000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [10, 4294967295] |

**Description**:

Used when limit k8s api list entry size.

#### K8s API List Maximum Interval {#inputs.resources.kubernetes.api_list_max_interval}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.api_list_max_interval`

Upgrade from old version: `static_config.kubernetes-api-list-interval`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      api_list_max_interval: 10m
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10m', '30d'] |

**Description**:

Interval of listing resource when watcher idles

#### Ingress Flavour {#inputs.resources.kubernetes.ingress_flavour}

**Tags**:

<mark></mark>
<mark>deprecated</mark>

**FQCN**:

`inputs.resources.kubernetes.ingress_flavour`

Upgrade from old version: `static_config.ingress-flavour`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      ingress_flavour: kubernetes
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

#### Pod MAC Collection Method {#inputs.resources.kubernetes.pod_mac_collection_method}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.resources.kubernetes.pod_mac_collection_method`

Upgrade from old version: `static_config.kubernetes-poller-type`

**Default value**:
```yaml
inputs:
  resources:
    kubernetes:
      pod_mac_collection_method: adaptive
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| adaptive | |
| active | |
| passive | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

In active mode, deepflow-agent enters the netns of other Pods through
setns syscall to query the MAC and IP addresses. In this mode, the setns
operation requires the SYS_ADMIN permission. In passive mode deepflow-agent
calculates the MAC and IP addresses used by Pods by capturing ARP/ND traffic.
When set to adaptive, active mode will be used first.

### Pull Resource From Controller {#inputs.resources.pull_resource_from_controller}

Configurations for deepflow-server on pulling resources from controller.
DeepFlow-agent will not read this section.

#### Domain Filter {#inputs.resources.pull_resource_from_controller.domain_filter}

**Tags**:

`hot_update`

**FQCN**:

`inputs.resources.pull_resource_from_controller.domain_filter`

Upgrade from old version: `domains`

**Default value**:
```yaml
inputs:
  resources:
    pull_resource_from_controller:
      domain_filter:
      - '0'
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Default value `0` means all domains, or can be set to a list of lcuuid of a
series of domains, you can get lcuuid through 'deepflow-ctl domain list'.

Note: The list of MAC and IP addresses is used by deepflow-agent to inject tags
into data. This configuration can reduce the number and frequency of MAC and
IP addresses delivered by deepflow-server to deepflow-agent. When there is no
cross-domain service request, deepflow-server can be configured to only deliver
the information in the local domain to deepflow-agent.

#### Only K8s Pod IP in Local Cluster {#inputs.resources.pull_resource_from_controller.only_kubernetes_pod_ip_in_local_cluster}

**Tags**:

`hot_update`

**FQCN**:

`inputs.resources.pull_resource_from_controller.only_kubernetes_pod_ip_in_local_cluster`

Upgrade from old version: `pod_cluster_internal_ip`

**Default value**:
```yaml
inputs:
  resources:
    pull_resource_from_controller:
      only_kubernetes_pod_ip_in_local_cluster: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

The list of MAC and IP addresses is used by deepflow-agent to inject tags
into data. This configuration can reduce the number and frequency of MAC and IP
addresses delivered by deepflow-server to deepflow-agent. When the Pod IP is not
used for direct communication between the K8s cluster and the outside world,
deepflow-server can be configured to only deliver the information in the local
K8s cluster to deepflow-agent.

## Integration {#inputs.integration}

### Enabled {#inputs.integration.enabled}

**Tags**:

`hot_update`

**FQCN**:

`inputs.integration.enabled`

Upgrade from old version: `external_agent_http_proxy_enabled`

**Default value**:
```yaml
inputs:
  integration:
    enabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to enable receiving external data sources such as Prometheus,
Telegraf, OpenTelemetry, and SkyWalking.

### Listen Port {#inputs.integration.listen_port}

**Tags**:

`hot_update`

**FQCN**:

`inputs.integration.listen_port`

Upgrade from old version: `external_agent_http_proxy_port`

**Default value**:
```yaml
inputs:
  integration:
    listen_port: 38086
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

Listen port of the data integration socket.

### Compression {#inputs.integration.compression}

#### Trace {#inputs.integration.compression.trace}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.compression.trace`

Upgrade from old version: `static_config.external-agent-http-proxy-compressed`

**Default value**:
```yaml
inputs:
  integration:
    compression:
      trace: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to compress the integrated trace data received by deepflow-agent. The compression
ratio is about 5:1~10:1. Turning on this feature will result in higher CPU consumption
of deepflow-agent.

#### Profile {#inputs.integration.compression.profile}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.compression.profile`

Upgrade from old version: `static_config.external-agent-http-proxy-profile-compressed`

**Default value**:
```yaml
inputs:
  integration:
    compression:
      profile: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to compress the integrated profile data received by deepflow-agent. The compression
ratio is about 5:1~10:1. Turning on this feature will result in higher CPU consumption
of deepflow-agent.

### Prometheus Extra Labels {#inputs.integration.prometheus_extra_labels}

Support for getting extra labels from headers in http requests from RemoteWrite.

#### Enabled {#inputs.integration.prometheus_extra_labels.enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.enabled`

Upgrade from old version: `static_config.prometheus-extra-config.enabled`

**Default value**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Prometheus extra labels switch.

#### Extra Labels {#inputs.integration.prometheus_extra_labels.extra_labels}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.extra_labels`

Upgrade from old version: `static_config.prometheus-extra-config.labels`

**Default value**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      extra_labels: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Labels list. Labels in this list are sent. Label is a string
matching the regular expression `[a-zA-Z_][a-zA-Z0-9_]*`

#### Label Key Total Length Limit {#inputs.integration.prometheus_extra_labels.label_length}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.label_length`

Upgrade from old version: `static_config.prometheus-extra-config.labels-limit`

**Default value**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      label_length: 1024
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [1024, 1048576] |

**Description**:

The limit of the total length of parsed extra Prometheus label keys.

#### Value Total Length Limit {#inputs.integration.prometheus_extra_labels.value_length}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.prometheus_extra_labels.value_length`

Upgrade from old version: `static_config.prometheus-extra-config.values-limit`

**Default value**:
```yaml
inputs:
  integration:
    prometheus_extra_labels:
      value_length: 4096
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [4096, 4194304] |

**Description**:

The limit of the total length of parsed extra Prometheus label values.

### Feature Control {#inputs.integration.feature_control}

#### Profile Integration Disabled {#inputs.integration.feature_control.profile_integration_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.profile_integration_disabled`

Upgrade from old version: `static_config.external-profile-integration-disabled`

**Default value**:
```yaml
inputs:
  integration:
    feature_control:
      profile_integration_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

#### Trace Integration Disabled {#inputs.integration.feature_control.trace_integration_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.trace_integration_disabled`

Upgrade from old version: `static_config.external-trace-integration-disabled`

**Default value**:
```yaml
inputs:
  integration:
    feature_control:
      trace_integration_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

#### Metric Integration Disabled {#inputs.integration.feature_control.metric_integration_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.metric_integration_disabled`

Upgrade from old version: `static_config.external-metric-integration-disabled`

**Default value**:
```yaml
inputs:
  integration:
    feature_control:
      metric_integration_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

#### Log Integration Disabled {#inputs.integration.feature_control.log_integration_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`inputs.integration.feature_control.log_integration_disabled`

Upgrade from old version: `static_config.external-log-integration-disabled`

**Default value**:
```yaml
inputs:
  integration:
    feature_control:
      log_integration_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

## Vector {#inputs.vector}

### Vector Component Enabled {#inputs.vector.enabled}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.vector.enabled`

**Default value**:
```yaml
inputs:
  vector:
    enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

The switcher control for Vector component running.

### Vector Component Config {#inputs.vector.config}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`inputs.vector.config`

**Default value**:
```yaml
inputs:
  vector:
    config: null
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

The detail config for Vector Component, all availble config keys could be found in [vector.dev](https://vector.dev/docs/reference/configuration)
Here's an example for how to capture kubernetes logs、host metrics in virtual machine and kubelet metrics in kubernetes. It'll send to DeepFlow-Agent as output.

scrape host metrics:
`K8S_NODE_NAME_FOR_DEEPFLOW` only required in k8s container environment
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

scrape kubernetes metrics
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

scrape kubernentes logs (capture DeepFlow Pod logs as example, if other Pod logs is required, update `extra_label_selector` add custom filters)
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

use http_client or socket to dial a remote server for testing
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

# Processors {#processors}

## Packet {#processors.packet}

### Policy {#processors.packet.policy}

#### Fast-path Map Size {#processors.packet.policy.fast_path_map_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.fast_path_map_size`

Upgrade from old version: `static_config.fast-path-map-size`

**Default value**:
```yaml
processors:
  packet:
    policy:
      fast_path_map_size: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 10000000] |

**Description**:

When set to 0, deepflow-agent will automatically adjust the map size
according to `global.limits.max_memory`.
Note: In practice, it should not be set to less than 8000.

#### Fast-path Disabled {#processors.packet.policy.fast_path_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.fast_path_disabled`

Upgrade from old version: `static_config.fast-path-disabled`

**Default value**:
```yaml
processors:
  packet:
    policy:
      fast_path_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When set to `true`, deepflow-agent will not use fast path.

#### Forward Table Capacity {#processors.packet.policy.forward_table_capacity}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.forward_table_capacity`

Upgrade from old version: `static_config.forward-capacity`

**Default value**:
```yaml
processors:
  packet:
    policy:
      forward_table_capacity: 16384
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [16384, 64000000] |

**Description**:

The size of the forwarding table, which is used to store MAC-IP information，
When this value is larger, the more memory usage may be.

#### Max First-path Level {#processors.packet.policy.max_first_path_level}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.policy.max_first_path_level`

Upgrade from old version: `static_config.first-path-level`

**Default value**:
```yaml
processors:
  packet:
    policy:
      max_first_path_level: 8
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 16] |

**Description**:

DDBS algorithm level.

When this value is larger, the memory overhead is smaller, but the
performance of policy matching is worse.

### TCP Header {#processors.packet.tcp_header}

#### Block Size {#processors.packet.tcp_header.block_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.tcp_header.block_size`

Upgrade from old version: `static_config.packet-sequence-block-size`

**Default value**:
```yaml
processors:
  packet:
    tcp_header:
      block_size: 256
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [16, 8192] |

**Description**:

When generating TCP header data, each flow uses one block to compress and
store multiple TCP headers, and the block size can be set here.

#### Sender Queue Size {#processors.packet.tcp_header.sender_queue_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.tcp_header.sender_queue_size`

Upgrade from old version: `static_config.packet-sequence-queue-size`

**Default value**:
```yaml
processors:
  packet:
    tcp_header:
      sender_queue_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues (to UniformCollectSender):
- 1-packet-sequence-block-to-uniform-collect-sender

#### Header Fields Flag {#processors.packet.tcp_header.header_fields_flag}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.tcp_header.header_fields_flag`

Upgrade from old version: `static_config.packet-sequence-flag`

**Default value**:
```yaml
processors:
  packet:
    tcp_header:
      header_fields_flag: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 255] |

**Description**:

packet-sequence-flag determines which fields need to be reported, the default
value is `0`, which means the feature is disabled, and `255`, which means all fields
need to be reported all fields corresponding to each bit:
```
| FLAG | SEQ | ACK | PAYLOAD_SIZE | WINDOW_SIZE | OPT_MSS | OPT_WS | OPT_SACK |
    7     6     5              4             3         2        1          0
```

### PCAP Stream {#processors.packet.pcap_stream}

#### Receiver Queue Size {#processors.packet.pcap_stream.receiver_queue_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.receiver_queue_size`

Upgrade from old version: `static_config.pcap.queue-size`

**Default value**:
```yaml
processors:
  packet:
    pcap_stream:
      receiver_queue_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues:
- 1-mini-meta-packet-to-pcap

#### Sender Queue Size {#processors.packet.pcap_stream.sender_queue_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.sender_queue_size`

**Default value**:
```yaml
processors:
  packet:
    pcap_stream:
      sender_queue_size: 8192
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [4096, 64000000] |

**Description**:

The length of the following queues:
- 2-pcap-batch-to-sender

#### Buffer Size Per Flow {#processors.packet.pcap_stream.buffer_size_per_flow}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.buffer_size_per_flow`

Upgrade from old version: `static_config.pcap.flow-buffer-size`

**Default value**:
```yaml
processors:
  packet:
    pcap_stream:
      buffer_size_per_flow: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [64, 64000000] |

**Description**:

PCap buffer size per flow. Will flush the flow when reach this limit.

#### Total Buffer Size {#processors.packet.pcap_stream.total_buffer_size}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.total_buffer_size`

Upgrade from old version: `static_config.pcap.buffer-size`

**Default value**:
```yaml
processors:
  packet:
    pcap_stream:
      total_buffer_size: 88304
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

Total PCap buffer size. Will flush all flows when reach this limit.

#### Flush Interval {#processors.packet.pcap_stream.flush_interval}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.packet.pcap_stream.flush_interval`

Upgrade from old version: `static_config.pcap.flush-interval`

**Default value**:
```yaml
processors:
  packet:
    pcap_stream:
      flush_interval: 1m
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '10m'] |

**Description**:

Flushes the PCap buffer of a flow if it has not been flushed for this interval.

### TOA (TCP Option Address) {#processors.packet.toa}

#### Sender Queue Size {#processors.packet.toa.sender_queue_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.toa.sender_queue_size`

Upgrade from old version: `static_config.toa-sender-queue-size`

**Default value**:
```yaml
processors:
  packet:
    toa:
      sender_queue_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues:
- 1-socket-sync-toa-info-queue

#### Cache Size {#processors.packet.toa.cache_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.packet.toa.cache_size`

Upgrade from old version: `static_config.toa-lru-cache-size`

**Default value**:
```yaml
processors:
  packet:
    toa:
      cache_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 64000000] |

**Description**:

Size of tcp option address info cache size.

## Request Log {#processors.request_log}

### Application Protocol Inference {#processors.request_log.application_protocol_inference}

#### Inference Maximum Retries {#processors.request_log.application_protocol_inference.inference_max_retries}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_max_retries`

Upgrade from old version: `static_config.l7-protocol-inference-max-fail-count`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_max_retries: 128
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 10000] |

**Description**:

The agent records the application protocol resolution results of each server through a hash table, including the
protocol, the number of continuous resolution failures, and the last resolution time

When an app protocol for Flow has never been successfully resolved, a hash table is used to decide which protocols
to try to resolve:
- If the result is not found in the hash table, or the result is not available (the protocol is unknown, or the
  number of failures exceeds the limit, or the time is more than inference_result_ttl from the current time)
  - If the number of failures has been exceeded, Flow is marked as prohibited for resolution for a period of
    inference_result_ttl
  - Otherwise, iterate through all open application protocols and try to parse them
    - When the parsing is successful, the protocol, parsing time, and number of failures (0) are updated to the hash
      table to keep the successful parsing results fresh
    - When parsing fails, the parsing time and number of failures (+1) are updated to the hash table so that the failed
      attempts can be accumulated, and subsequent attempts will be prohibited after the accumulation exceeds the threshold
  - If a specific, available protocol is found in the hash table, it is attempted using that protocol
    - When the parsing is successful, the protocol, parsing time, and number of failures (0) are updated to the hash table
      to keep the successful parsing results fresh
    - When parsing fails, the parsing time and number of failures (+1) are updated to the hash table so that the failed
      attempts can be accumulated, and subsequent attempts will be prohibited after the accumulation exceeds the threshold

Once a Flow is successfully parsed once, it will only use that protocol type to try to parse it once, and there is no need
to query the hash table。
Each time the resolution is successful, the protocol in the hash table (for HTTP2/gRPC needs to be updated), the resolution
time, and the number of failures will be updated.

#### Inference Result TTL {#processors.request_log.application_protocol_inference.inference_result_ttl}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_result_ttl`

Upgrade from old version: `static_config.l7-protocol-inference-ttl`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_result_ttl: 60s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0ns', '1d'] |

**Description**:

deepflow-agent will mark the application protocol for each
<vpc, ip, protocol, port> tuple. In order to avoid misidentification caused by IP
changes, the validity period after successfully identifying the protocol will be
limited to this value.

#### Inference whitelist {#processors.request_log.application_protocol_inference.inference_whitelist}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.application_protocol_inference.inference_whitelist`

**Default value**:
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

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Application protocol port whitelist, currently only supports eBPF traffic. When eBPF data is on the whitelist,
the application table is no longer used to query the application protocol. The corresponding application protocol
is obtained by polling all currently supported protocols. Having too much data on the whitelist greatly reduces the
processing performance of eBPF data.

Configuration Key:
- process_name: Process name, regular expressions are not supported
- port_list: Port Whitelist

##### Process name {#processors.request_log.application_protocol_inference.inference_whitelist.process_name}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_whitelist.process_name`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_whitelist:
      - process_name: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Process name

##### Port list {#processors.request_log.application_protocol_inference.inference_whitelist.port_list}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.inference_whitelist.port_list`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      inference_whitelist:
      - port_list: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

Port list

#### Enabled Protocols {#processors.request_log.application_protocol_inference.enabled_protocols}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.enabled_protocols`

Upgrade from old version: `static_config.l7-protocol-enabled`

**Default value**:
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

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Turning off some protocol identification can reduce deepflow-agent resource consumption.
Supported protocols: [https://www.deepflow.io/docs/features/l7-protocols/overview/](https://www.deepflow.io/docs/features/l7-protocols/overview/)
<mark>Oracle and TLS is only supported in the Enterprise Edition.</mark>

#### Protocol Special Config {#processors.request_log.application_protocol_inference.protocol_special_config}

##### Oracle {#processors.request_log.application_protocol_inference.protocol_special_config.oracle}

###### Integer Byte Order {#processors.request_log.application_protocol_inference.protocol_special_config.oracle.is_be}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.oracle.is_be`

Upgrade from old version: `static_config.oracle-parse-config.is-be`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        oracle:
          is_be: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether the oracle integer encode is big endian.

###### Integer Compressed {#processors.request_log.application_protocol_inference.protocol_special_config.oracle.int_compressed}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.oracle.int_compressed`

Upgrade from old version: `static_config.oracle-parse-config.int-compress`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        oracle:
          int_compressed: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether the oracle integer encode is compress.

###### Response 0x04 with Extra Byte {#processors.request_log.application_protocol_inference.protocol_special_config.oracle.resp_0x04_extra_byte}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.oracle.resp_0x04_extra_byte`

Upgrade from old version: `static_config.oracle-parse-config.resp-0x04-extra-byte`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        oracle:
          resp_0x04_extra_byte: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Due to the response with data id 0x04 has different struct in
different version, it may has one byte before row affect.

##### ISO8583 {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583}

###### Value Translation {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583.translation_enabled}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.iso8583.translation_enabled`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        iso8583:
          translation_enabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to perform field value translation.

###### PAN Obfuscate {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583.pan_obfuscate}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.iso8583.pan_obfuscate`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        iso8583:
          pan_obfuscate: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to obfuscate the Primary Account Number (PAN).

###### Extract Fields {#processors.request_log.application_protocol_inference.protocol_special_config.iso8583.extract_fields}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.iso8583.extract_fields`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        iso8583:
          extract_fields: 2,7,11,32,33
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Extracted fields are displayed in `data native tags`.
  - Example: `extract_fields: 0,2-33`
Field Reference:

| Field No. | Description |
|-----------|-------------|
| 0   | Message Type Identifier (MTI) |
| 1   | Bitmap |
| 2   | Primary Account Number (PAN) |
| 3   | Processing Code |
| 4   | Amount, Transaction |
| 5   | Amount, Settlement |
| 6   | Amount, Cardholder Billing |
| 7   | Transmission Date & Time |
| 9   | Conversion Rate, Settlement |
| 10  | Conversion Rate, Cardholder Billing |
| 11  | System Trace Audit Number (STAN) |
| 12  | Local Transaction Time |
| 13  | Local Transaction Date |
| 14  | Expiration Date |
| 15  | Settlement Date |
| 16  | Conversion Date |
| 18  | Merchant Type |
| 19  | Acquiring Institution Country Code |
| 22  | POS Entry Mode Code |
| 23  | Card Sequence Number |
| 25  | POS Condition Code |
| 26  | POS PIN Capture Code |
| 28  | Transaction Fee |
| 32  | Acquiring Institution Identification Code |
| 33  | Forwarding Institution Identification Code |
| 35  | Track 2 Data |
| 36  | Track 3 Data |
| 37  | Retrieval Reference Number (RRN) |
| 38  | Authorization Identification Response |
| 39  | Response Code |
| 41  | Card Acceptor Terminal ID |
| 42  | Card Acceptor ID Code |
| 43  | Card Acceptor Name/Location |
| 44  | Additional Response Data |
| 45  | Track 1 Data |
| 48  | Additional Data – Private |
| 49  | Currency Code, Transaction |
| 50  | Currency Code, Settlement |
| 51  | Currency Code, Cardholder Billing |
| 52  | PIN Data |
| 53  | Security Related Control Information |
| 54  | Additional Amounts (Balance) |
| 55  | ICC Data (EMV Data) |
| 56  | Additional Data |
| 57  | Additional Transaction Data |
| 59  | Detail Data / Reserved for National Use |
| 60  | Reserved for Private Use |
| 61  | Cardholder Authentication Information |
| 62  | Switch Data |
| 63  | Network Data |
| 70  | Network Management Information Code |
| 90  | Original Data Elements |
| 96  | Message Security Code |
| 100 | Receiving Institution Identification Code |
| 102 | Account Identification 1 |
| 103 | Account Identification 2 |
| 104 | Additional Data |
| 113 | Additional Data |
| 116 | Additional Data |
| 117 | Additional Data |
| 121 | Reserved by China UnionPay (CUPS) |
| 122 | Reserved for Acquirer |
| 123 | Reserved for Issuer |
| 125 | Additional Data |
| 126 | Additional Data |
| 128 | Message Authentication Code (MAC) |

##### MySQL {#processors.request_log.application_protocol_inference.protocol_special_config.mysql}

###### Decompress MySQL Payload {#processors.request_log.application_protocol_inference.protocol_special_config.mysql.decompress_payload}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.mysql.decompress_payload`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        mysql:
          decompress_payload: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Some MySQL packets have payload compressed with LZ77 algorithm. Enable this option to decompress payload on parsing.
Set to false to disable decompression for better performance.
ref: [MySQL Source Code Documentation](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_compression.html)

##### Grpc {#processors.request_log.application_protocol_inference.protocol_special_config.grpc}

###### Enable gRPC stream data {#processors.request_log.application_protocol_inference.protocol_special_config.grpc.streaming_data_enabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.protocol_special_config.grpc.streaming_data_enabled`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      protocol_special_config:
        grpc:
          streaming_data_enabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When enabled, all gRPC packets are considered to be of the `stream` type, and the `data` will be reported,
and the rrt calculation of the response will use the `grpc-status` field.

#### custom protocol parsing {#processors.request_log.application_protocol_inference.custom_protocols}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.application_protocol_inference.custom_protocols`

**Default value**:
```yaml
processors:
  request_log:
    application_protocol_inference:
      custom_protocols: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Custom protocol parsing configuration, which can be used to parse custom protocols through simple rules.
Example:
```yaml
- protocol_name: "your_protocol_name" # Protocol name, corresponding to l7_flow_log.l7_protocol_str
  pre_filter:
    port_list: 1-65535 # Pre-filter port, which can improve parsing performance
  request_characters:  # Multiple features are ORed
    - character: # Multiple match_keywords are ANDed
      - match_keyword: abc  # Feature string
        match_type: "string" # Possible values: "string", "hex"
        match_ignore_case: false # wheather ignore case when match keywords, when match_type == string effected, default: false
        match_from_beginning: false # Whether to match from the beginning of the payload
  response_characters:
    - character:
      - match_keyword: 0123af
        match_type: "hex"
        match_from_beginning: false
```

### Filters {#processors.request_log.filters}

#### Port Number Pre-filters {#processors.request_log.filters.port_number_prefilters}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.port_number_prefilters`

Upgrade from old version: `static_config.l7-protocol-ports`

**Default value**:
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

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Port-list example:
```
HTTP: 80,1000-2000
HTTP2: 1-65535
```

NOTE:
1. HTTP2 and TLS are only used for Kprobe, not applicable to Uprobe.
   All data obtained through Uprobe is not subject to port restrictions.
   - Supported protocols: [https://www.deepflow.io/docs/features/l7-protocols/overview/](https://www.deepflow.io/docs/features/l7-protocols/overview/)
   - <mark>Oracle and TLS is only supported in the Enterprise Edition.</mark>
2. Attention: use `HTTP2` for `gRPC` Protocol.

#### Tag Filters {#processors.request_log.filters.tag_filters}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters`

Upgrade from old version: `static_config.l7-log-blacklist`

**Default value**:
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

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Tag filter example:
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
        # other protocols
```
A l7_flow_log blacklist can be configured for each protocol, preventing request logs matching
the blacklist from being collected by the agent or included in application performance metrics.
It's recommended to only place non-business request logs like heartbeats or health checks in this
blacklist. Including business request logs might lead to breaks in the distributed tracing tree.

Supported protocols: [https://www.deepflow.io/docs/features/l7-protocols/overview/](https://www.deepflow.io/docs/features/l7-protocols/overview/)

<mark>Oracle and TLS is only supported in the Enterprise Edition.</mark>

##### $HTTP Tag Filters {#processors.request_log.filters.tag_filters.HTTP}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol`

**Default value**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

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

###### Field Name {#processors.request_log.filters.tag_filters.HTTP.field_name}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP.field_name`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol.field-name`

**Default value**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
        - field_name: ''
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| endpoint | |
| request_type | |
| request_domain | |
| request_resource | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Match field name.

###### Operator {#processors.request_log.filters.tag_filters.HTTP.operator}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP.operator`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol.operator`

**Default value**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
        - operator: ''
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| equal | |
| prefix | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Match operator.

###### Field Value {#processors.request_log.filters.tag_filters.HTTP.field_value}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.tag_filters.HTTP.field_value`

Upgrade from old version: `static_config.l7-log-blacklist.$protocol.value`

**Default value**:
```yaml
processors:
  request_log:
    filters:
      tag_filters:
        HTTP:
        - field_value: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Match field value.

#### Unconcerned DNS NXDOMAIN {#processors.request_log.filters.unconcerned_dns_nxdomain_response_suffixes}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.filters.unconcerned_dns_nxdomain_response_suffixes`

Upgrade from old version: `static_config.l7-protocol-advanced-features.unconcerned-dns-nxdomain-response-suffixes`

**Default value**:
```yaml
processors:
  request_log:
    filters:
      unconcerned_dns_nxdomain_response_suffixes: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

You might not be concerned about certain DNS NXDOMAIN errors and may wish to ignore
them. For example, when a K8s Pod tries to resolve an external domain name, it first
concatenates it with the internal domain suffix of the cluster and attempts to resolve
it. All these attempts will receive an NXDOMAIN reply before it finally requests the
original domain name directly, and these errors may not be of concern to you. In such
cases, you can configure their `response_result` suffix here, so that the corresponding
`response_status` in the l7_flow_log is forcibly set to `Success`.

#### cBPF data disabled {#processors.request_log.filters.cbpf_disabled}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.filters.cbpf_disabled`

**Default value**:
```yaml
processors:
  request_log:
    filters:
      cbpf_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When disabled, deepflow-agent will not generate request_log from packet data.

### Timeouts {#processors.request_log.timeouts}

#### TCP Request Timeout {#processors.request_log.timeouts.tcp_request_timeout}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.timeouts.tcp_request_timeout`

Upgrade from old version: `static_config.rrt-tcp-timeout`

**Default value**:
```yaml
processors:
  request_log:
    timeouts:
      tcp_request_timeout: 300s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '3600s'] |

**Description**:

The timeout of l7 log info rrt calculate, when rrt exceed the value will act as timeout and will not
calculate the sum and average and will not merge the request and response in session aggregate. the value
must greater than the timeout period of the TCP type in configured `processors.request_log.timeouts.session_aggregate`
(For example, the HTTP2 default is 120s) and less than 3600s on tcp.

#### UDP Request Timeout {#processors.request_log.timeouts.udp_request_timeout}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.timeouts.udp_request_timeout`

Upgrade from old version: `static_config.rrt-udp-timeout`

**Default value**:
```yaml
processors:
  request_log:
    timeouts:
      udp_request_timeout: 150s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['10s', '300s'] |

**Description**:

The timeout of l7 log info rrt calculate, when rrt exceed the value will act as timeout and will not
calculate the sum and average and will not merge the request and response in session aggregate. the value
must greater than the timeout period of the UDP type in configured `processors.request_log.timeouts.session_aggregate`
(For example, the DNS default is 15s) and less than 300 on udp.

#### Session Aggregate Window Duration {#processors.request_log.timeouts.session_aggregate_window_duration}

**Tags**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`processors.request_log.timeouts.session_aggregate_window_duration`

Upgrade from old version: `static_config.l7-log-session-aggr-timeout`

**Default value**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate_window_duration: 120s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['20s', '300s'] |

**Description**:

l7_flow_log aggregate window.

#### Application Session Aggregate Timeouts {#processors.request_log.timeouts.session_aggregate}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.timeouts.session_aggregate`

**Default value**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Set the aggregation timeout for each application.
The default values is 15s for DNS and TLS, 120s for others.

Example:
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

##### Protocol {#processors.request_log.timeouts.session_aggregate.protocol}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.timeouts.session_aggregate.protocol`

**Default value**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate:
      - protocol: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Protocol Name for timeout setting.

##### Timeout {#processors.request_log.timeouts.session_aggregate.timeout}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.timeouts.session_aggregate.timeout`

**Default value**:
```yaml
processors:
  request_log:
    timeouts:
      session_aggregate:
      - timeout: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |

**Description**:

Set the timeout for the application. The timeout period of TCP application protocols must be less than
`processors.request_log.timeouts.tcp_request_timeout`, and the timeout period of UDP must be less than
`processors.request_log.timeouts.udp_request_timeout`.

### Tag Extraction {#processors.request_log.tag_extraction}

#### Tracing Tag {#processors.request_log.tag_extraction.tracing_tag}

##### HTTP Real Client {#processors.request_log.tag_extraction.tracing_tag.http_real_client}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.http_real_client`

Upgrade from old version: `http_log_proxy_client`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        http_real_client:
        - X_Forwarded_For
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

It is used to extract the real client IP field in the HTTP header,
such as X-Forwarded-For, etc. Leave it empty to disable this feature.
If multiple values are specified, the first match will be used.
Fields rewritten by plugins have the highest priority.

##### X-Request-ID {#processors.request_log.tag_extraction.tracing_tag.x_request_id}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.x_request_id`

Upgrade from old version: `http_log_x_request_id`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        x_request_id:
        - X_Request_ID
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

It is used to extract the fields in the HTTP header that are used
to uniquely identify the same request before and after the gateway,
such as X-Request-ID, etc. This feature can be turned off by setting
it to empty.
If multiple values are specified, the first match will be used.
Fields rewritten by plugins have the highest priority.

##### Multiple TraceID Collection {#processors.request_log.tag_extraction.tracing_tag.multiple_trace_id_collection}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.multiple_trace_id_collection`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        multiple_trace_id_collection: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When configured as `false`, only one TraceID is collected.
When configured as `true`, multiple TraceIDs will be collected.

##### APM TraceID {#processors.request_log.tag_extraction.tracing_tag.apm_trace_id}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.apm_trace_id`

Upgrade from old version: `http_log_trace_id`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        apm_trace_id:
        - traceparent
        - sw8
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Used to extract the TraceID field in HTTP and RPC headers, supports filling
in multiple values separated by commas. This feature can be turned off by
setting it to empty.
If multiple values are specified, the first match will be used.
Fields rewritten by plugins have the highest priority.

##### Copy APM TraceID {#processors.request_log.tag_extraction.tracing_tag.copy_apm_trace_id}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.copy_apm_trace_id`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        copy_apm_trace_id: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When set to true, the APM TraceID will be copied to the attribute.apm_trace_id field.

##### APM SpanID {#processors.request_log.tag_extraction.tracing_tag.apm_span_id}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.tag_extraction.tracing_tag.apm_span_id`

Upgrade from old version: `http_log_span_id`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      tracing_tag:
        apm_span_id:
        - traceparent
        - sw8
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Used to extract the SpanID field in HTTP and RPC headers, supports filling
in multiple values separated by commas. This feature can be turned off by
setting it to empty.
If multiple values are specified, the first match will be used.
Fields rewritten by plugins have the highest priority.

#### HTTP Endpoint {#processors.request_log.tag_extraction.http_endpoint}

##### Extraction Disabled {#processors.request_log.tag_extraction.http_endpoint.extraction_disabled}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.extraction_disabled`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.disabled`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        extraction_disabled: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

HTTP endpoint extration is enabled by default.

##### Match Rules {#processors.request_log.tag_extraction.http_endpoint.match_rules}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.match_rules`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.match-rules`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        match_rules:
        - keep_segments: 2
          url_prefix: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Extract endpoint according to the following rules:
- Find a longest prefix that can match according to the principle of
  "longest prefix matching"
- Intercept the first few paragraphs in URL (the content between two
  / is regarded as one paragraph) as endpoint

By default, two segments are extracted from the URL. For example, the
URL is `/a/b/c?query=xxx`, whose segment is 3, extracts `/a/b` as the
endpoint.

###### URL Prefix {#processors.request_log.tag_extraction.http_endpoint.match_rules.url_prefix}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.match_rules.url_prefix`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.match-rules.prefix`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        match_rules:
        - url_prefix: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

HTTP URL prefix.

###### Keep Segments {#processors.request_log.tag_extraction.http_endpoint.match_rules.keep_segments}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.http_endpoint.match_rules.keep_segments`

Upgrade from old version: `static_config.l7-protocol-advanced-features.http-endpoint-extraction.match-rules.keep-segments`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      http_endpoint:
        match_rules:
        - keep_segments: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

Keep how many segments.

#### Custom Fields {#processors.request_log.tag_extraction.custom_fields}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_fields`

Upgrade from old version: `static_config.l7-protocol-advanced-features.extra-log-fields`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP: []
        HTTP2: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| HTTP | |
| HTTP2 | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Configuration to extract the customized header fields of HTTP, HTTP2, gRPC protocol etc.

Example:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: "user-agent"
        - field_name: "cookie"
```

Attention: use `HTTP2` for `gRPC` Protocol.

##### $HTTP Custom Fields {#processors.request_log.tag_extraction.custom_fields.HTTP}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_fields.HTTP`

Upgrade from old version: `static_config.l7-protocol-advanced-features.extra-log-fields.$protocol`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Configuration to extract the customized header fields of HTTP, HTTP2, gRPC protocol etc.

Example:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: "user-agent"
        - field_name: "cookie"
```

Attention: use `HTTP2` for `gRPC` Protocol.

###### Field Name {#processors.request_log.tag_extraction.custom_fields.HTTP.field_name}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_fields.HTTP.field_name`

Upgrade from old version: `static_config.l7-protocol-advanced-features.extra-log-fields.$protocol.field-name`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_fields:
        HTTP:
        - field_name: ''
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Field name.

#### Custom Fields Policies {#processors.request_log.tag_extraction.custom_field_policies}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`processors.request_log.tag_extraction.custom_field_policies`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      custom_field_policies: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | dict |

**Description**:

Custom field extraction policy, used to extract possible custom fields from L7 protocols via simple rules.
When both plugin extraction and custom extraction policies match, the priority is as follows:
1. Plugin extraction
2. Custom field policies extraction
3. Agent default extraction
Example:
```yaml
- policy_name: "my_policy" # Policy name
  protocol_name: HTTP # Protocol name. If you want to parse Grpc, configure as HTTP2. Possible values: HTTP/HTTP2/Dubbo/SofaRPC/Custom/...
  custom_protocol_name: "my_protocol"  # Effective only when protocol_name is Custom. Note: At this time, there must be a `processors.request_log.application_protocol_inference.custom_protocols` config, and the custom protocol name must match exactly, otherwise parsing will not work.
  filters:
    traffic_direction: both # Search in request, response, or both. Default is both.
    port_list: 1-65535 # Can be used to filter by port.
    feature_string: "" # For pre-matching Payload extraction, does not apply to header_field type.
  # Whether to save the original payload.
  # Note: This configuration is only effective when the "filters" are met.
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
  - name: "my_field" # Configured field
    # Field extraction type, possible values and meanings:
    # - `http_url_field`: Extract field from HTTP URL parameters at the end of the URL, e.g. `?key=value&key2=value2`
    # - `header_field`: Extract field from protocol header section (HTTP/Dubbo/SofaRPC/...); for HTTP, e.g. `key: value`
    # - `payload_json_value`: Extract field from JSON payload, e.g. `"key": 1`, `"key": "value"`, `"key": None`, etc.
    # - `payload_xml_value`: Extract field from XML payload, e.g. `<key attr="xxx">value</key>`
    # - `payload_hessian2_value`: Extract field from payload using Hessian2 encoding.
    # - `sql_insertion_column`: Extract column from SQL insert statement, e.g. `INSERT INTO table (column1, column2) VALUES (value1, value2)`. Currently only MySQL is supported and only the first column's value can be extracted.
    type: "http_url_field"
    # Matching rule
    match:
      # Match type, possible values: "string" and "path"
      # When set to "string":
      # - For http_url_field and header_field, matches key; for sql_insertion_column, matches SQL insert column name.
      # - For payload_json_value and payload_xml_value, matches JSON or XML content and takes the first matched element as the result.
      # "path" type applies only to parse_json_value and parse_xml_value, supports extraction using hierarchical syntax like "aaa.bbb.ccc" for JSON and XML content.
      type: "string"
      keyword: "abc"
      # Ignore case. Default: false. Only valid when `type` is "string".
      ignore_case: false
      # Apply field rule to all leaf nodes. Default: false.
      # Only effective for parse_json_value and parse_xml_value types.
      # When set to true:
      # - Apply keyword matching to all leaf nodes in JSON or XML content.
      # - Only attribute_name in output is valid, serving as the prefix of the output result. The output name uses attribute_name as prefix and the leaf node's path as suffix, separated by ".".
      # - This field cannot be used in compound_fields.
      all_leaves: false
    # Post-processing. Note that settings are executed in order.
    # Configuration format:
    # - type: post_processing_type
    #   settings:
    #   - key: setting_key
    #     value: setting_value
    # Supported types for 'type' are:
    # - remap
    # - obfuscate
    # - url_decode
    # - base64_decode
    # - parse_json_value
    # - parse_xml_value
    # - parse_key_value
    # See below for details and configuration of each type
    post:
    # remap is used to map the extraction result to another value
    # Supported settings:
    # - dictionary_name: Name of the dictionary
    - type: remap
      settings:
      - key: dictionary_name
        value: dict_1
    # obfuscate is used for masking/desensitizing extracted results
    # Supported settings:
    # - mask: The character used for masking, default is *, supports only ascii characters
    # - preset: Use a prebuilt masking method, valid values are:
    #   - id-card-name: Chinese ID card name masking (show only the first character of the name)
    #   - id-card-number: Chinese ID card number masking (show only first 6 and last 4 digits)
    #   - phone-number: Phone number masking (hide at least 4 characters in the middle)
    # - range: Indicates which characters (by index) to mask with *, e.g. retain only the first and last character
    - type: obfuscate
      settings:
      - key: mask
        value: *
      - key: preset
        value: id-card-name
      - key: range
        value: "1, -1" # Mask from the second to the last character, keeping only the first character
      - key: range # Multiple 'range' settings represent multiple masked ranges
        value: "6, -5" # Mask from the 7th to the 5th from last character
    # url_decode is used to decode the extracted result using URL-decoding
    - type: url_decode
    # base64_decode is used to decode the extracted result using Base64, output must be valid UTF-8
    - type: base64_decode
    # parse_json_value is used to further parse the extracted result as JSON
    # Supported settings:
    # - keyword: Key word to match
    # - type: Value type, options are string/path
    # - ignore_case: Whether to ignore case, default false
    # - skip: Skip the first N matches, use from this index
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
    # parse_xml_value is used to further parse the extracted result as XML
    # Supported settings:
    # - keyword: Key word to match
    # - type: Value type, options are string/path
    # - ignore_case: Whether to ignore case, default false
    # - skip: Skip the first N matches, use from this index
    - type: parse_xml_value
      # This configuration is the same as fields->match, but in key/value form.
      # Also, skip is supported to indicate which matching result to take.
      settings:
      - key: keyword
        value: xyz
      - key: type
        value: string
      - key: ignore_case
        value: false
      - key: skip
        value: 0
    # parse_key_value parses the result as key-value pairs
    # Supported settings:
    # - key_value_pair_separator: Separator between key-value pairs, default ","
    # - key_value_separator: Separator between key and value, default "="
    # - keyword: Key word to match
    # - ignore_case: Whether to ignore case, default false
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
    # Validate if the post-processed result is legal
    verify:
      check_charset: false # Can be used to check if extraction result is valid
      primary_charset: ["digits", "alphabets", "hanzi"] # Charsets used to check extraction result; optional values: digits/alphabets/hanzi
      special_characters: ".-_" # Additional special characters allowed in result charset
    output:
      attribute_name: "xyz" # This field will appear in calling log as attribute.xyz. Default is empty; if empty, this field will not be added to the attribute.
      metric_name: "xyz" # This field will appear in calling log as metrics.xyz. Default is empty.
      rewrite_native_tag:
        # Fill one of the following fields to overwrite the corresponding value
        # Note: This requires support in the corresponding protocol, otherwise the configuration will not take effect
        # When overwriting response_code, the original non-empty value will be saved into the attribute as `sys_response_code`
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
        # When remapping, the input will be mapped using the configured dictionary. If empty, it will not take effect
        # Note: The whitelist/blacklist in condition match the remapped result
        remap: dict_1
        condition:
          enum_whitelist: [] # Whitelist: when the extraction result is in the list, overwrite. If empty, does not take effect.
          enum_blacklist: [] # Blacklist: when result matches any in the list, do not update.
      # Match to these arrays by extraction value. If matched, rewrite response_status to the corresponding value.
      rewrite_response_status:
        ok_values: []
        client_error_values: []
        server_error_values: []
        default_status: "" # Optional: ok/client_error/server_error. If empty and no match, will NOT rewrite. Default is empty.
      # Field output priority. Default is 0. Range 0-255. Smaller values have higher priority.
      # For fields that keep only one value (except trace_id), only the one with the smallest priority is kept.
      # For fields with multiple values (trace_id), output them in order from highest to lowest priority.
      priority: 0
  # Directly use a constant value as the field value
  const_fields:
  - value: "123"
    # Output configuration, refer to the "output" section of "fields"
    # "metric", "rewrite_response_status", and the "condition" and "remap" in "rewrite_native_tag" are not supported here
    output:
      attribute_name: "xyz"
      rewrite_native_tag:
        name: version
      priority: 0
  # Compound fields allow you to use configured fields or native_tags as input fields for formatted output
  # If the corresponding field or native_tag is not resolved or is empty, the output will not be produced
  compound_fields:
  - format: "{field1_name}-{field2_name}" # Output format. field1_name and field2_name are the configured field names
                                          # Native tags can also be used as an input field, but note that the configured fields take precedence.
    output: # Configure as described in "output" section of "fields"
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

#### Obfuscate Protocols {#processors.request_log.tag_extraction.obfuscate_protocols}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.obfuscate_protocols`

Upgrade from old version: `static_config.l7-protocol-advanced-features.obfuscate-enabled-protocols`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      obfuscate_protocols:
      - Redis
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| MySQL | |
| PostgreSQL | |
| HTTP | |
| HTTP2 | |
| Redis | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

For the sake of data security, the data of the protocol that needs
to be desensitized is configured here and is not processed by default.
Obfuscated fields mainly include:
- Authorization information
- Value information in various statements

#### Raw Data {#processors.request_log.tag_extraction.raw}

控制提取 L7 日志对应的原始数据

##### Length of extracted request header {#processors.request_log.tag_extraction.raw.error_request_header}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_request_header`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_request_header: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**Description**:

When set to a value greater than 0, for call logs with abnormal states, the request Header is automatically collected
(truncated to $error_request_header bytes) into attribute.request_header. Recommended for temporary use only for the
following reasons:
- On one hand, directly storing the header carries a certain risk of exposing sensitive information, which may
  lead to compliance issues.
- On the other hand, it can also cause all request header (currently only for the HTTP protocol) to be cached
  until the response status is parsed to determine whether to send them, consuming collector resources.

##### Length of extracted request header {#processors.request_log.tag_extraction.raw.error_response_header}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_response_header`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_response_header: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**Description**:

When set to a value greater than 0, for call logs with abnormal states, the response Header is automatically collected
(truncated to $error_response_header bytes) into attribute.response_header.

##### Length of extracted response header {#processors.request_log.tag_extraction.raw.error_request_payload}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_request_payload`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_request_payload: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**Description**:

When set to a value greater than 0, for call logs with abnormal status, the request payload is automatically
collected (truncated to $error_request_payload) into attribute.request_payload. Recommended for temporary use
only for the following reasons:
- On one hand, directly storing the payload carries a certain risk of exposing sensitive information, which may
  lead to compliance issues.
- On the other hand, it can also cause all request payloads (currently only for the HTTP protocol) to be cached
  until the response status is parsed to determine whether to send them, consuming collector resources.

##### Length of extracted request header {#processors.request_log.tag_extraction.raw.error_response_payload}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tag_extraction.raw.error_response_payload`

**Default value**:
```yaml
processors:
  request_log:
    tag_extraction:
      raw:
        error_response_payload: 256
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 16384] |

**Description**:

The default value is 256, which means collecting the first 256 bytes of an abnormal response payload and placing
them into attribute.response_payload. When set to 0, it means that abnormal response payloads are not collected.

### Tunning {#processors.request_log.tunning}

#### Payload Truncation {#processors.request_log.tunning.payload_truncation}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.tunning.payload_truncation`

Upgrade from old version: `l7_log_packet_size`

**Default value**:
```yaml
processors:
  request_log:
    tunning:
      payload_truncation: 1024
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [256, 65535] |

**Description**:

The maximum data length used for application protocol identification,
note that the effective value is less than the value of
`inputs.cbpf.tunning.max_capture_packet_size`.

NOTE: For eBPF data, the largest valid value is 16384.

#### Session Aggregate Slot Capacity {#processors.request_log.tunning.session_aggregate_slot_capacity}

**Tags**:

<mark>agent_restart</mark>
<mark>deprecated</mark>

**FQCN**:

`processors.request_log.tunning.session_aggregate_slot_capacity`

Upgrade from old version: `static_config.l7-log-session-slot-capacity`

**Default value**:
```yaml
processors:
  request_log:
    tunning:
      session_aggregate_slot_capacity: 1024
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 1000000] |

**Description**:

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

#### Session Aggregate Max Entries {#processors.request_log.tunning.session_aggregate_max_entries}

**Tags**:

`hot_update`

**FQCN**:

`processors.request_log.tunning.session_aggregate_max_entries`

**Default value**:
```yaml
processors:
  request_log:
    tunning:
      session_aggregate_max_entries: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [16384, 10000000] |

**Description**:

The maximum number of l7_flow_log entries cached for merging into a session.
If the total number of l7_flow_log entries exceeds this configuration,
the oldest entry will be sent without merging, setting its response status to `Unknown`.

#### Consistent Timestamp in L7 Metrics {#processors.request_log.tunning.consistent_timestamp_in_l7_metrics}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.request_log.tunning.consistent_timestamp_in_l7_metrics`

**Default value**:
```yaml
processors:
  request_log:
    tunning:
      consistent_timestamp_in_l7_metrics: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When this configuration is enabled, for the same session, response-related metrics (such as response
count, latency, exceptions) are recorded in the time slot corresponding to when the request occurred,
rather than the time slot of the response itself. This means that when calculating metrics for
requests and responses within a session, a consistent timestamp based on the time of the request
occurrence is used.

## Flow Log {#processors.flow_log}

### Time Window {#processors.flow_log.time_window}

#### Maximum Tolerable Packet Delay {#processors.flow_log.time_window.max_tolerable_packet_delay}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.time_window.max_tolerable_packet_delay`

Upgrade from old version: `static_config.packet-delay`

**Default value**:
```yaml
processors:
  flow_log:
    time_window:
      max_tolerable_packet_delay: 1s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '20s'] |

**Description**:

The timestamp carried by the packet captured by AF_PACKET may be delayed
from the current clock, especially in heavy traffic scenarios, which may be
as high as nearly 10s.
This also affects FlowMap aggregation window size.

#### Extra Tolerable Flow Delay {#processors.flow_log.time_window.extra_tolerable_flow_delay}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.time_window.extra_tolerable_flow_delay`

Upgrade from old version: `static_config.second-flow-extra-delay-second`

**Default value**:
```yaml
processors:
  flow_log:
    time_window:
      extra_tolerable_flow_delay: 0s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['0s', '20s'] |

**Description**:

Extra tolerance for QuadrupleGenerator receiving flows.
Affects 1s/1m QuadrupleGenerator aggregation window size.

### Conntrack (a.k.a. Flow Map) {#processors.flow_log.conntrack}

#### Flow Flush Interval {#processors.flow_log.conntrack.flow_flush_interval}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_flush_interval`

Upgrade from old version: `static_config.flow.flush-interval`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_flush_interval: 1s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1m'] |

**Description**:

Flow generation delay time in FlowMap, used to increase the window size
in downstream processing units to avoid pushing the window too fast.

#### Flow Generation {#processors.flow_log.conntrack.flow_generation}

##### Server Ports {#processors.flow_log.conntrack.flow_generation.server_ports}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.server_ports`

Upgrade from old version: `static_config.server-ports`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        server_ports: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

Service port list, priority lower than TCP SYN flags.

##### Cloud Traffic Ignore MAC {#processors.flow_log.conntrack.flow_generation.cloud_traffic_ignore_mac}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.cloud_traffic_ignore_mac`

Upgrade from old version: `static_config.flow.ignore-tor-mac`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        cloud_traffic_ignore_mac: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When the MAC addresses of the two-way traffic collected at the same
location are asymmetrical, the traffic cannot be aggregated into a Flow.
You can set this value at this time. Only valid for Cloud (not IDC) traffic.

##### Ignore L2End {#processors.flow_log.conntrack.flow_generation.ignore_l2_end}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.ignore_l2_end`

Upgrade from old version: `static_config.flow.ignore-l2-end`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        ignore_l2_end: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

For Cloud traffic, only the MAC address corresponding to the side with
L2End = true is matched when generating the flow. Set this value to `true` to
force a double-sided MAC address match and only aggregate traffic with
exactly equal MAC addresses.

##### IDC Traffic Ignore VLAN {#processors.flow_log.conntrack.flow_generation.idc_traffic_ignore_vlan}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`processors.flow_log.conntrack.flow_generation.idc_traffic_ignore_vlan`

Upgrade from old version: `static_config.flow.ignore-idc-vlan`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      flow_generation:
        idc_traffic_ignore_vlan: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When the VLAN of the two-way traffic collected at the same location
are asymmetrical, the traffic cannot be aggregated into a Flow. You can
set this value at this time. Only valid for IDC (not Cloud) traffic.

#### Timeouts {#processors.flow_log.conntrack.timeouts}

##### Established {#processors.flow_log.conntrack.timeouts.established}

**Tags**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.established`

Upgrade from old version: `static_config.flow.established-timeout`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        established: 300s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**Description**:

Timeouts for TCP State Machine - Established.

##### Closing RST {#processors.flow_log.conntrack.timeouts.closing_rst}

**Tags**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.closing_rst`

Upgrade from old version: `static_config.flow.closing-rst-timeout`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        closing_rst: 35s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**Description**:

Timeouts for TCP State Machine - Closing Reset.

##### Opening RST {#processors.flow_log.conntrack.timeouts.opening_rst}

**Tags**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.opening_rst`

Upgrade from old version: `static_config.flow.opening-rst-timeout`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        opening_rst: 1s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**Description**:

Timeouts for TCP State Machine - Opening Reset.

##### Others {#processors.flow_log.conntrack.timeouts.others}

**Tags**:

`hot_update`

**FQCN**:

`processors.flow_log.conntrack.timeouts.others`

Upgrade from old version: `static_config.flow.others-timeout`

**Default value**:
```yaml
processors:
  flow_log:
    conntrack:
      timeouts:
        others: 5s
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | duration |
| Range | ['1s', '1d'] |

**Description**:

Timeouts for TCP State Machine - Others.

### Tunning {#processors.flow_log.tunning}

#### FlowMap Hash Slots {#processors.flow_log.tunning.flow_map_hash_slots}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.flow_map_hash_slots`

Upgrade from old version: `static_config.flow.flow-slots-size`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      flow_map_hash_slots: 131072
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**Description**:

Since FlowAggregator is the first step in all processing, this value
is also widely used in other hash tables such as QuadrupleGenerator,
Collector, etc.

#### Concurrent Flow Limit {#processors.flow_log.tunning.concurrent_flow_limit}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.concurrent_flow_limit`

Upgrade from old version: `static_config.flow.flow-count-limit`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      concurrent_flow_limit: 65535
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**Description**:

Maximum number of flows that can be stored in FlowMap. When `inputs.cbpf.common.capture_mode` is `Physical Mirror`
and concurrent_flow_limit is less than or equal to 65535, it will be forced to u32::MAX.

#### RRT Cache Capacity {#processors.flow_log.tunning.rrt_cache_capacity}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.rrt_cache_capacity`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      rrt_cache_capacity: 16000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**Description**:

The capacity of the RRT Cache table in FlowMap. This table is used to calculate RRT latency metrics. If it is too large,
it will cause high memory usage in the agent; if it is too small, RRT metrics may be missing.

#### Memory Pool Size {#processors.flow_log.tunning.memory_pool_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.memory_pool_size`

Upgrade from old version: `static_config.flow.memory-pool-size`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      memory_pool_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**Description**:

This value is used to set max length of memory pool in FlowMap
Memory pools are used for frequently create and destroy objects like
FlowNode, FlowLog, etc.

#### Maximum Size of Batched Buffer {#processors.flow_log.tunning.max_batched_buffer_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.max_batched_buffer_size`

Upgrade from old version: `static_config.batched-buffer-size-limit`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      max_batched_buffer_size: 131072
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1024, 64000000] |

**Description**:

Only TaggedFlow allocation is affected at the moment.
Structs will be allocated in batch to minimalize malloc calls.
Total memory size of a batch will not exceed this limit.
A number larger than 128K is not recommended because the default
MMAP_THRESHOLD is 128K, allocating chunks larger than 128K will
result in calling mmap and more page faults.

#### FlowAggregator Queue Size {#processors.flow_log.tunning.flow_aggregator_queue_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.flow_aggregator_queue_size`

Upgrade from old version: `static_config.flow.flow-aggr-queue-size`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      flow_aggregator_queue_size: 65535
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues:
- 2-second-flow-to-minute-aggrer

#### FlowGenerator Queue Size {#processors.flow_log.tunning.flow_generator_queue_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.flow_generator_queue_size`

Upgrade from old version: `static_config.flow-queue-size`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      flow_generator_queue_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues:
- 1-tagged-flow-to-quadruple-generator
- 1-tagged-flow-to-app-protocol-logs
- 0-{flow_type}-{port}-packet-to-tagged-flow (flow_type: sflow, netflow)

#### QuadrupleGenerator Queue Size {#processors.flow_log.tunning.quadruple_generator_queue_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`processors.flow_log.tunning.quadruple_generator_queue_size`

Upgrade from old version: `static_config.quadruple-queue-size`

**Default value**:
```yaml
processors:
  flow_log:
    tunning:
      quadruple_generator_queue_size: 262144
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [262144, 64000000] |

**Description**:

The length of the following queues:
- 2-flow-with-meter-to-second-collector
- 2-flow-with-meter-to-minute-collector

# Outputs {#outputs}

## Socket {#outputs.socket}

### Data Socket Type {#outputs.socket.data_socket_type}

**Tags**:

`hot_update`

**FQCN**:

`outputs.socket.data_socket_type`

Upgrade from old version: `collector_socket_type`

**Default value**:
```yaml
outputs:
  socket:
    data_socket_type: TCP
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| TCP | |
| UDP | |
| FILE | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

It can only be set to FILE in standalone mode, in which case
l4_flow_log and l7_flow_log will be written to local files.

### NPB Socket Type {#outputs.socket.npb_socket_type}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.socket.npb_socket_type`

Upgrade from old version: `npb_socket_type`

**Default value**:
```yaml
outputs:
  socket:
    npb_socket_type: RAW_UDP
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| UDP | |
| RAW_UDP | |
| TCP | |
| ZMQ | |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

RAW_UDP uses RawSocket to send UDP packets, which has the highest
performance, but there may be compatibility issues in some environments.

### RAW_UDP QoS Bypass {#outputs.socket.raw_udp_qos_bypass}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.socket.raw_udp_qos_bypass`

Upgrade from old version: `static_config.enable-qos-bypass`

**Default value**:
```yaml
outputs:
  socket:
    raw_udp_qos_bypass: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When sender uses RAW_UDP to send data, this feature can be enabled to
improve performance. Linux Kernel >= 3.14 is required. Note that the data
sent when this feature is enabled cannot be captured by tcpdump.

### Multiple Sockets To Ingester {#outputs.socket.multiple_sockets_to_ingester}

**Tags**:

`hot_update`

**FQCN**:

`outputs.socket.multiple_sockets_to_ingester`

Upgrade from old version: `static_config.multiple-sockets-to-ingester`

**Default value**:
```yaml
outputs:
  socket:
    multiple_sockets_to_ingester: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When set to true, deepflow-agent will send data with multiple sockets to Ingester,
which has higher performance, but will bring more impact to the firewall.

## Flow Log and Request Log {#outputs.flow_log}

### Filters {#outputs.flow_log.filters}

#### Capture Network Types for L4 {#outputs.flow_log.filters.l4_capture_network_types}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l4_capture_network_types`

Upgrade from old version: `l4_log_tap_types`

**Default value**:
```yaml
outputs:
  flow_log:
    filters:
      l4_capture_network_types:
      - 0
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| -1 | Disabled |
| 0 | All TAPs |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

The list of TAPs to collect l4_flow_log, you can also set a list of TAPs to
be collected.

#### Capture Network Types for L7 {#outputs.flow_log.filters.l7_capture_network_types}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l7_capture_network_types`

Upgrade from old version: `l7_log_store_tap_types`

**Default value**:
```yaml
outputs:
  flow_log:
    filters:
      l7_capture_network_types:
      - 0
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| -1 | Disabled |
| 0 | All TAPs |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

The list of TAPs to collect l7_flow_log, you can also set a list of TAPs to
be collected.

#### Ignored Observation Points for L4 {#outputs.flow_log.filters.l4_ignored_observation_points}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l4_ignored_observation_points`

Upgrade from old version: `l4_log_ignore_tap_sides`

**Default value**:
```yaml
outputs:
  flow_log:
    filters:
      l4_ignored_observation_points: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | rest, Other NIC |
| 1 | c, Client NIC |
| 2 | s, Server NIC |
| 4 | local, Local NIC |
| 9 | c-nd, Client K8s Node |
| 10 | s-nd, Server K8s Node |
| 17 | c-hv, Client VM Hypervisor |
| 18 | s-hv, Server VM Hypervisor |
| 25 | c-gw-hv, Client-side Gateway Hypervisor |
| 26 | s-gw-hv, Server-side Gateway Hypervisor |
| 33 | c-gw, Client-side Gateway |
| 34 | s-gw, Server-side Gateway |
| 41 | c-p, Client Process |
| 42 | s-p, Server Process |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

Use the value of tap_side to control which l4_flow_log should be ignored for
collection. This configuration also applies to tcp_sequence and pcap data in
the Enterprise Edition. Default value `[]` means store everything.

#### Ignored Observation Points for L7 {#outputs.flow_log.filters.l7_ignored_observation_points}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_log.filters.l7_ignored_observation_points`

Upgrade from old version: `l7_log_ignore_tap_sides`

**Default value**:
```yaml
outputs:
  flow_log:
    filters:
      l7_ignored_observation_points: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | rest, Other NIC |
| 1 | c, Client NIC |
| 2 | s, Server NIC |
| 4 | local, Local NIC |
| 9 | c-nd, Client K8s Node |
| 10 | s-nd, Server K8s Node |
| 17 | c-hv, Client VM Hypervisor |
| 18 | s-hv, Server VM Hypervisor |
| 25 | c-gw-hv, Client-side Gateway Hypervisor |
| 26 | s-gw-hv, Server-side Gateway Hypervisor |
| 33 | c-gw, Client-side Gateway |
| 34 | s-gw, Server-side Gateway |
| 41 | c-p, Client Process |
| 42 | s-p, Server Process |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

Use the value of observation points to control which l7_flow_log should be ignored for
collection. The default value `[]` means that all observation points are collected.

### Aggregators {#outputs.flow_log.aggregators}

#### Health Check Flow Log Aggregation {#outputs.flow_log.aggregators.aggregate_health_check_l4_flow_log}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_log.aggregators.aggregate_health_check_l4_flow_log`

**Default value**:
```yaml
outputs:
  flow_log:
    aggregators:
      aggregate_health_check_l4_flow_log: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Agent will mark the following types of flows as `close_type = normal end-client reset`:
- Client sends SYN, server replies SYN-ACK, client sends RST
- Client sends SYN, server replies SYN-ACK, client sends ACK, client sends RST

This type of traffic is normal load balancer backend host inspection traffic and does not carry any meaningful application layer payload.

When this configuration item is set to `true`, Agent will reset the client port number of the flow log to 0 before aggregating the output,
thereby reducing bandwidth and storage overhead.

### Throttles {#outputs.flow_log.throttles}

#### L4 Throttle {#outputs.flow_log.throttles.l4_throttle}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_log.throttles.l4_throttle`

Upgrade from old version: `l4_log_collect_nps_threshold`

**Default value**:
```yaml
outputs:
  flow_log:
    throttles:
      l4_throttle: 10000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Per Second |
| Range | [100, 1000000] |

**Description**:

The maximum number of rows of l4_flow_log sent per second, when the actual
number of upstream rows exceeds this value, reservoir sampling is applied to
limit the actual number of rows sent.

#### L7 Throttle {#outputs.flow_log.throttles.l7_throttle}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_log.throttles.l7_throttle`

Upgrade from old version: `l7_log_collect_nps_threshold`

**Default value**:
```yaml
outputs:
  flow_log:
    throttles:
      l7_throttle: 10000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Per Second |
| Range | [100, 1000000] |

**Description**:

The maximum number of rows of l7_flow_log sent per second, when the actual
number of rows exceeds this value, sampling is triggered.

### Tunning {#outputs.flow_log.tunning}

#### Collector Queue Size {#outputs.flow_log.tunning.collector_queue_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.flow_log.tunning.collector_queue_size`

Upgrade from old version: `static_config.flow-sender-queue-size`

**Default value**:
```yaml
outputs:
  flow_log:
    tunning:
      collector_queue_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues:
- 3-flow-to-collector-sender
- 3-protolog-to-collector-sender

## Flow Metrics {#outputs.flow_metrics}

### Enabled {#outputs.flow_metrics.enabled}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.enabled`

Upgrade from old version: `collector_enabled`

**Default value**:
```yaml
outputs:
  flow_metrics:
    enabled: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When disabled, deepflow-agent will not send metrics and logging data
collected using eBPF and cBPF.

Attention: set to false will also disable l4_flow_log and l7_flow_log.

### Filters {#outputs.flow_metrics.filters}

#### Inactive Server Port Aggregation {#outputs.flow_metrics.filters.inactive_server_port_aggregation}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.inactive_server_port_aggregation`

Upgrade from old version: `inactive_server_port_enabled`

**Default value**:
```yaml
outputs:
  flow_metrics:
    filters:
      inactive_server_port_aggregation: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When enabled, deepflow-agent will not generate detailed metrics for each
inactive port (ports that only receive data, not send data), and the data of
all inactive ports will be aggregated into the metrics with a tag
'server_port = 0'.

#### Inactive IP Aggregation {#outputs.flow_metrics.filters.inactive_ip_aggregation}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.inactive_ip_aggregation`

Upgrade from old version: `inactive_ip_enabled`

**Default value**:
```yaml
outputs:
  flow_metrics:
    filters:
      inactive_ip_aggregation: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When enabled, deepflow-agent will not generate detailed metrics for each
inactive IP address (IP addresses that only receive data, not send data), and
the data of all inactive IP addresses will be aggregated into the metrics with
a tag 'ip = 0'.

#### NPM Metrics {#outputs.flow_metrics.filters.npm_metrics}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.npm_metrics`

Upgrade from old version: `l4_performance_enabled`

**Default value**:
```yaml
outputs:
  flow_metrics:
    filters:
      npm_metrics: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When closed, deepflow-agent only collects some basic throughput metrics.

#### NPM Concurrent Metrics {#outputs.flow_metrics.filters.npm_metrics_concurrent}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.npm_metrics_concurrent`

**Default value**:
```yaml
outputs:
  flow_metrics:
    filters:
      npm_metrics_concurrent: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When closed, deepflow-agent does not calculate metrics concurrent.

#### APM Metrics {#outputs.flow_metrics.filters.apm_metrics}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.apm_metrics`

Upgrade from old version: `l7_metrics_enabled`

**Default value**:
```yaml
outputs:
  flow_metrics:
    filters:
      apm_metrics: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

When closed, deepflow-agent will not collect RED (request/error/delay) metrics.

#### Second Metrics {#outputs.flow_metrics.filters.second_metrics}

**Tags**:

`hot_update`

**FQCN**:

`outputs.flow_metrics.filters.second_metrics`

Upgrade from old version: `vtap_flow_1s_enabled`

**Default value**:
```yaml
outputs:
  flow_metrics:
    filters:
      second_metrics: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Second granularity metrics.

### Tunning {#outputs.flow_metrics.tunning}

#### Sender Queue Size {#outputs.flow_metrics.tunning.sender_queue_size}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.flow_metrics.tunning.sender_queue_size`

Upgrade from old version: `static_config.collector-sender-queue-size`

**Default value**:
```yaml
outputs:
  flow_metrics:
    tunning:
      sender_queue_size: 65536
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [65536, 64000000] |

**Description**:

The length of the following queues:
- 3-doc-to-collector-sender

## NPB (Network Packet Broker) {#outputs.npb}

### Maximum MTU {#outputs.npb.max_mtu}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.max_mtu`

Upgrade from old version: `mtu`

**Default value**:
```yaml
outputs:
  npb:
    max_mtu: 1500
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | byte |
| Range | [500, 10000] |

**Description**:

Maximum MTU allowed when using UDP for NPB.

Attention: Public cloud service providers may modify the content of the
tail of the UDP packet whose packet length is close to 1500 bytes. When
using UDP transmission, it is recommended to set a slightly smaller value.

### RAW_UDP VLAN Tag {#outputs.npb.raw_udp_vlan_tag}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.raw_udp_vlan_tag`

Upgrade from old version: `output_vlan`

**Default value**:
```yaml
outputs:
  npb:
    raw_udp_vlan_tag: 0
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 4095] |

**Description**:

When using RAW_UDP Socket to transmit UDP data, this value can be used to
set the VLAN tag. Default value `0` means no VLAN tag.

### Extra VLAN Header {#outputs.npb.extra_vlan_header}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.extra_vlan_header`

Upgrade from old version: `npb_vlan_mode`

**Default value**:
```yaml
outputs:
  npb:
    extra_vlan_header: 0
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| 0 | None |
| 1 | 802.1Q |
| 2 | QinQ |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |

**Description**:

Whether to add an extra 802.1Q header to NPB traffic, when this value is
set, deepflow-agent will insert a VLAN Tag into the NPB traffic header, and
the value is the lower 12 bits of TunnelID in the VXLAN header.

### Traffic Global Dedup {#outputs.npb.traffic_global_dedup}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.traffic_global_dedup`

Upgrade from old version: `npb_dedup_enabled`

**Default value**:
```yaml
outputs:
  npb:
    traffic_global_dedup: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to enable global (distributed) traffic deduplication for the
NPB feature.

### Target Port {#outputs.npb.target_port}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.target_port`

Upgrade from old version: `static_config.npb-port`

**Default value**:
```yaml
outputs:
  npb:
    target_port: 4789
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [1, 65535] |

**Description**:

Server port for NPB.

### Custom VXLAN Flags {#outputs.npb.custom_vxlan_flags}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.custom_vxlan_flags`

Upgrade from old version: `static_config.vxlan-flags`

**Default value**:
```yaml
outputs:
  npb:
    custom_vxlan_flags: 255
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Range | [0, 255] |

**Description**:

NPB uses the first byte of the VXLAN Flag to identify the sending traffic to
prevent the traffic sent by NPB from being collected by deepflow-agent.

Attention: To ensure that the VNI bit is set, the value configured here will
be used after |= 0b1000_0000. Therefore, this value cannot be directly
configured as 0b1000_0000.

### Overlay VLAN Header Trimming {#outputs.npb.overlay_vlan_header_trimming}

**Tags**:

<mark>agent_restart</mark>
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.overlay_vlan_header_trimming`

Upgrade from old version: `static_config.ignore-overlay-vlan`

**Default value**:
```yaml
outputs:
  npb:
    overlay_vlan_header_trimming: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

This configuration only ignores the VLAN header in the captured original message
and does not affect the configuration item: npb_vlan_mode

### Maximum Tx Throughput {#outputs.npb.max_tx_throughput}

**Tags**:

`hot_update`
<mark>ee_feature</mark>

**FQCN**:

`outputs.npb.max_tx_throughput`

Upgrade from old version: `max_npb_bps`

**Default value**:
```yaml
outputs:
  npb:
    max_tx_throughput: 1000
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | int |
| Unit | Mbps |
| Range | [1, 100000] |

**Description**:

Maximum traffic rate allowed for npb sender.

## Compression {#outputs.compression}

### Application_Log {#outputs.compression.application_log}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.application_log`

**Default value**:
```yaml
outputs:
  compression:
    application_log: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to compress the integrated application log data received by deepflow-agent. The compression
ratio is about 5:1~20:1. Turning on this feature will result in higher CPU consumption
of deepflow-agent.

### Pcap {#outputs.compression.pcap}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.pcap`

**Default value**:
```yaml
outputs:
  compression:
    pcap: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to compress the captured pcap data received by deepflow-agent. The compression
ratio is about 5:1~10:1. Turning on this feature will result in higher CPU consumption
of deepflow-agent.

### Request Log {#outputs.compression.l7_flow_log}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.l7_flow_log`

**Default value**:
```yaml
outputs:
  compression:
    l7_flow_log: true
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to compress the l7 flow log. The compression ratio is about 8:1.
Turning on this feature will result in higher CPU consumption of deepflow-agent.

### Flow Log {#outputs.compression.l4_flow_log}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`outputs.compression.l4_flow_log`

**Default value**:
```yaml
outputs:
  compression:
    l4_flow_log: false
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | bool |

**Description**:

Whether to compress the l4 flow log.

# Plugins {#plugins}

Plugin support
When both plugins and custom extraction policies match, the priority is:
1. Plugin extraction
2. Custom field policies extraction
3. Agent default extraction

## Wasm Plugins {#plugins.wasm_plugins}

**Tags**:

`hot_update`

**FQCN**:

`plugins.wasm_plugins`

Upgrade from old version: `wasm_plugins`

**Default value**:
```yaml
plugins:
  wasm_plugins: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Wasm plugin need to load in agent

## SO Plugins {#plugins.so_plugins}

**Tags**:

`hot_update`

**FQCN**:

`plugins.so_plugins`

Upgrade from old version: `so_plugins`

**Default value**:
```yaml
plugins:
  so_plugins: []
```

**Enum options**:
| Value | Note                         |
| ----- | ---------------------------- |
| _DYNAMIC_OPTIONS_ | _DYNAMIC_OPTIONS_ |

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

so plugin need to load in agent. so plugin use dlopen flag RTLD_LOCAL
and RTLD_LAZY to open the so file, it mean that the so must solve the
link problem by itself

# Dev {#dev}

## Feature Flags {#dev.feature_flags}

**Tags**:

<mark>agent_restart</mark>

**FQCN**:

`dev.feature_flags`

Upgrade from old version: `static_config.feature-flags`

**Default value**:
```yaml
dev:
  feature_flags: []
```

**Schema**:
| Key  | Value                        |
| ---- | ---------------------------- |
| Type | string |

**Description**:

Unreleased deepflow-agent features can be turned on by setting this switch.
