/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package model

var YamlVTapGroupConfig = []byte(`## Agent Group ID
vtap_group_id: g-xxxxxx

####################
## Resource Limit ##
####################
## CPU Limit
## Unit: number of logical cores. Default: 1. Range: [1, 100000]
## Note: deepflow-agent uses cgroups to limit CPU usage.
##   But please note that deepflow-agent running in K8s Pod
##   cannot be limited by this value, please configure it
##   through K8s Limit.
#max_cpus: 1

## Memory Limit
## Unit: M bytes. Default: 768. Range: [128, 100000]
## Note: deepflow-agent uses cgroups to limit memory usage.
##   But please note that deepflow-agent running in K8s Pod
##   cannot be limited by this value, please configure it
##   through K8s Limit.
#max_memory: 768

## System Free Memory Limit
## Unit: %. Default: 0. Range: [0, 100]
## Note: The limit of the percentage of system free memory.
##   When the free percentage is lower than 90% of this value,
##   the agent will will automatically restart.
#sys_free_memory_limit: 0

## Packet Capture Rate Limit
## Unit: Kpps. Default: 200. Range: [1, 1000000]
#max_collect_pps: 200

## NPB (Packet Broker) Traffic Limit
## Unit: Mbps. Default: 1000. Range: [1, 10000]
#max_npb_bps: 1000

## NPB (Packet Broker) Circuit Breaker Threshold
## Unit: Mbps. Default: 0. Range: [0, 10000]
## Note: When the outbound direction of the NPB interface
##   reaches or exceeds the threshold, the distribution will be
##   stopped, and then the distribution will be resumed if the
##   value is lower than (max_tx_bandwidth - max_npb_bps)*90%
##   within 5 consecutive monitoring intervals.
## Attention: When configuring this value, it must be greater
##   than max_npb_bps. 0 means disable this feature.
#max_tx_bandwidth: 0

## NPB Circuit Breaker Monitoring Interval
## Unit: second. Default: 10. Range: [1, 60]
## Note: monitoring interval for outbound traffic rate of NPB interface
#bandwidth_probe_interval: 10

## Remote Log Rate
## Unit: lines/hour. Default: 300. Range: [0, 10000]
## Note: deepflow-agent will send logs to deepflow-server, 0 means no limit.
#log_threshold: 300

## Log Level
## Default: INFO. options: DEBUG, INFO, WARNING, ERROR
#log_level: INFO

## Log File Size
## Unit: M bytes. Default: 1000. Range: [10, 10000]
#log_file_size: 1000

## Thread Limit
## Default: 500. Range: [1, 1000]
## Note: Maximum number of threads that deepflow-agent is allowed to launch.
#thread_threshold: 500

## Process Limit
## Default: 10. Range: [1, 100]
## Note: Maximum number of processes that deepflow-agent is allowed to launch.
#process_threshold: 10

#########################
## Basic Configuration ##
#########################
## Regular Expression for TAP (Traffic Access Point)
## Length: [0, 65535]
## Default:
##   Localhost:   lo
##   Common NIC:  eth.*|en[ospx].*
##   QEMU VM NIC: tap.*
##   Flannel:     veth.*
##   Calico:      cali.*
##   Cilium:      lxc.*
##   Kube-OVN:    [0-9a-f]+_h$
## Note: Regular expression of NIC name for collecting traffic
#tap_interface_regex: ^(tap.*|cali.*|veth.*|eth.*|en[ospx].*|lxc.*|lo|[0-9a-f]+_h)$

## Traffic Capture Filter
## Length: [1, 512]
## Note: If not configured, all traffic will be collected. Please
##   refer to BPF syntax: https://biot.com/capstats/bpf.html
#capture_bpf:

## Maximum Packet Capture Length
## Unit: bytes. Default: 65535. Range: [128, 65535]
## Note: DPDK environment does not support this configuration.
#capture_packet_size: 65535

## Traffic Capture API
## Default: 0, means adaptive. Options: 0, 2 (AF_PACKET V2), 3 (AF_PACKET V3)
## Description: Traffic capture API in Linux environment
#capture_socket_type: 0

## Decapsulation Tunnel Protocols
## Default: [1, 3], means VXLAN and IPIP. Options: 1 (VXLAN), 2 (GRE), 3 (IPIP)
#decap_type:
#- 1
#- 3

## VM MAC Address Extraction
## Default: 0
## Options:
##   0: extracted from tap interface MAC address
##   1: extracted from tap interface name
##   2: extracted from the XML file of the virtual machine
## Note: How to extract the real MAC address of the virtual machine when the
##   agent runs on the KVM host
#if_mac_source: 0

## VM XML File Directory
## Default: /etc/libvirt/qemu/
## Length: [0, 100]
#vm_xml_path: /etc/libvirt/qemu/

## Configuration Synchronization Interval
## Unit: second. Default: 60. Range: [10, 3600]
#sync_interval: 60

## Maximum Escape Time
## Unit: seconds. Default: 3600. Range: [600, 2592000]
## Note: The maximum time that the agent is allowed to work normally when it
##   cannot connect to the server. After the timeout, the agent automatically
##   enters the disabled state.
#max_escape_seconds: 3600

## UDP maximum MTU, unit: bytes, default value: 1500, value range [500, 10000]
## Note: Maximum MTU allowed when using UDP to transfer data.
## Attention: Public cloud service providers may modify the content of the
##   tail of the UDP packet whose packet length is close to 1500 bytes. When
##   using UDP transmission, it is recommended to set a slightly smaller value.
#mtu: 1500

## Raw UDP VLAN Tag
## Default: 0, means no VLAN tag. Range: [0, 4095]
## Note: When using Raw Socket to transmit UDP data, this value can be used to
##   set the VLAN tag
#output_vlan: 0

## Request NAT IP
## Default: 0. Options: 0, 1
## Note: Used when deepflow-agent uses an external IP address to access
##   deepflow-server. For example, when deepflow-server is behind a NAT gateway,
##   or the host where deepflow-server is located has multiple node IP addresses
##   and different deepflow-agents need to access different node IPs, you can
##   set an additional NAT IP for each deepflow-server address, and modify this
##   value to 1.
#nat_ip_enabled: 0

## Log Retention Time
## Unit: days. Default: 30. Range: [7, 365]
#log_retention: 300

## Control Plane Server Port
## Default: 30035. Range: 1-65535
## Note: The control plane port used by deepflow-agent to access deepflow-server.
##   The default port within the same K8s cluster is 20035, and the default port
##   of deepflow-agent outside the cluster is 30035.
#proxy_controller_port: 30035

## Data Plane Server Port
## Default: 30033. Range: 1-65535
## Note: The data plane port used by deepflow-agent to access deepflow-server.
##   The default port within the same K8s cluster is 20033, and the default port
##   of deepflow-agent outside the cluster is 30033.
#analyzer_port: 30033

## Fixed Control Plane Server IP
## Note: When this value is set, deepflow-agent will use this IP to access the
##   control plane port of deepflow-server, which is usually used when
##   deepflow-server uses an external load balancer.
#proxy_controller_ip:

## Fixed Data Plane Server IP
## Note: When this value is set, deepflow-agent will use this IP to access the
##   data plane port of deepflow-server, which is usually used when
##   deepflow-server uses an external load balancer.
#analyzer_ip:

#############################
## Collector Configuration ##
#############################
## Data Socket Type
## Default: TCP. Options: TCP, UDP, FILE
## Note: It can only be set to FILE in standalone mode, in which case
##   l4_flow_log and l7_flow_log will be written to local files.
#collector_socket_type: TCP

## PCAP Socket Type
## Default: TCP. Options: TCP, UDP, RAW_UDP
## Note: RAW_UDP uses RawSocket to send UDP packets, which has the highest
##   performance, but there may be compatibility issues in some environments.
#compressor_socket_type: TCP

## HTTP Real Client Key
## Default: X-Forwarded-For.
## Note: It is used to extract the real client IP field in the HTTP header,
##   such as X-Forwarded-For, etc. Leave it empty to disable this feature.
#http_log_proxy_client: X-Forwarded-For

## HTTP X-Request-ID Key
## Default: X-Request-ID
## Note: It is used to extract the fields in the HTTP header that are used
##   to uniquely identify the same request before and after the gateway,
##   such as X-Request-ID, etc. This feature can be turned off by setting
##   it to empty.
#http_log_x_request_id: X-Request-ID

## TraceID Keys
## Default: traceparent, sw8.
## Note: Used to extract the TraceID field in HTTP and RPC headers, supports filling
##   in multiple values separated by commas. This feature can be turned off by
##   setting it to empty.
#http_log_trace_id: traceparent, sw8

## SpanID Keys
## Default: traceparent, sw8.
## Note: Used to extract the SpanID field in HTTP and RPC headers, supports filling
##   in multiple values separated by commas. This feature can be turned off by
##   setting it to empty.
#http_log_span_id: traceparent, sw8

## Protocol Identification Maximun Packet Length
## Default: 1024. Range: [256, 1500]
## Note: The maximum data length used for application protocol identification,
##   note that the effective value is less than or equal to the value of
##   capture_packet_size.
#l7_log_packet_size: 1024

## Maximum Sending Rate for l4_flow_log
## Default: 10000. Range: [100, [1000000]
## Note: The maximum number of rows of l4_flow_log sent per second, when the actual
##   number of rows exceeds this value, sampling is triggered.
#l4_log_collect_nps_threshold: 10000

## Maximum Sending Rate for l7_flow_log
## Default: 10000. Range: [100, [1000000]
## Note: The maximum number of rows of l7_flow_log sent per second, when the actual
##   number of rows exceeds this value, sampling is triggered.
#l7_log_collect_nps_threshold: 10000

#######################
## NPB Configuration ##
#######################
## NPB Socket Type
## Default: RAW_UDP. Options: UDP, RAW_UDP
## Note: RAW_UDP uses RawSocket to send UDP packets, which has the highest
##   performance, but there may be compatibility issues in some environments.
#npb_socket_type: RAW_UDP

## Inner Additional Header
## Default: 0, means none. Options: 0, 1 (Additional 802.1Q Header)
## Note: Whether to add an extra 802.1Q header to NPB traffic, when this value is
##   set, deepflow-agent will insert a VLAN Tag into the NPB traffic header, and
##   the value is the lower 12 bits of TunnelID in the VXLAN header.
#npb_vlan_mode: 0

##############################
## Management Configuration ##
##############################
## KVM/Host Metadata Synchronization
## Default: 0, means disabled. Options: 0 (disabled), 1 (enabled).
## Node: When enabled, deepflow-agent will automatically synchronize virtual
##   machine and network information on the KVM (or Host) to deepflow-server.
#platform_enabled: 0

## Self Log Sending
## Default: 1, means enabled. Options: 0 (disabled), 1 (enabled).
## Note: When enabled, deepflow-agent will send its own logs to deepflow-server.
#rsyslog_enabled: 1

## NTP Synchronization
## Default: 1, means enabled. Options: 0 (disabled), 1 (enabled).
## Note: Whether to synchronize the clock to the deepflow-server, this behavior
##   will not change the time of the deepflow-agent running environment.
#ntp_enabled: 1

## Resource Tag Synchronization Scope
## Default: 0, which means all domains, or can be set to a list of lcuuid of a
##   series of domains, you can get lcuuid through 'deepflow-ctl domain list'.
## Note: Usually used in multi-cluster environments to reduce the number and
##   frequency of resource tags synchronized to deepflow-agent.
#domains:
#- 0

## Pod IP Synchronization Scope
## Default: 0, which means all K8s cluster. Options: 0 (all cluster), 1 (self cluster).
## Note: Pod IP is generally not directly used for cross-K8s cluster communication.
##   Setting it to 1 can reduce the number and frequency of synchronizing resource
##   tags to deepflow-agent.
#pod_cluster_internal_ip: 0

########################
## Collector Switches ##
########################
## AutoMetrics & AutoLogging
## Default: 1. Options: 0 (disabled), 1 (enabled).
## Note: When disabled, deepflow-agent will not send metrics and logging data
##   collected using eBPF and cBPF.
#collector_enabled: 1

## Detailed Metrics for Inactive Port
## Default: 1. Options: 0 (disabled), 1 (enabled).
## Note: When closed, deepflow-agent will not generate detailed metrics for each
##   inactive port (ports that only receive data, not send data), and the data of
##   all inactive ports will be aggregated into the metrics with a tag
##   'server_port = 0'.
#inactive_server_port_enabled: 1

## Detailed Metrics for Inactive IP Address
## Default: 1. Options: 0 (disabled), 1 (enabled).
## Note: When closed, deepflow-agent will not generate detailed metrics for each
##   inactive IP address (IP addresses that only receive data, not send data), and
##   the data of all inactive IP addresses will be aggregated into the metrics with
##   a tag 'ip = 0'.
#inactive_ip_enabled: 1

## NPM Metrics
## Default: 1. Options: 0 (disabled), 1 (enabled).
## Note: When closed, deepflow-agent only collects some basic throughput metrics.
#l4_performance_enabled: 1

## APM Metrics
## Default: 1. Options: 0 (disabled), 1 (enabled).
## Note: When closed, deepflow-agent will not collect RED (request/error/delay) metrics.
#l7_metrics_enabled: 1

## Second Granularity Metrics
## Default: 1. Options: 0 (disabled), 1 (enabled).
#vtap_flow_1s_enabled: 1

## TAPs Collect l4_flow_log
## Default: 0, which means all TAPs. Options: -1 (disabled), 0 (all TAPs)
## Note: The list of TAPs to collect l4_flow_log, you can also set a list of TAPs to
##   be collected.
#l4_log_tap_types:
#- 0

## TAPs Collect l7_flow_log
## Default: 0, which means all TAPs. Options: -1 (disabled), 0 (all TAPs)
## Note: The list of TAPs to collect l7_flow_log, you can also set a list of TAPs to
##   be collected.
#l7_log_store_tap_types:
#- 0

## Data Integration Socket
## Default: 0. Options: 0 (disabled), 1 (enabled).
## Note: Whether to enable receiving external data sources such as Prometheus,
##   Telegraf, OpenTelemetry, and SkyWalking.
#external_agent_http_proxy_enabled: 0

## Listen Port of the Data Integration Socket
## Default: 38086. Options: [1, 65535]
#external_agent_http_proxy_port: 38086

##################
## NPB Switches ##
##################
## Global Deduplication
## Default: 1. Options: 0 (disabled), 1 (enabled).
## Note: Whether to enable global (distributed) traffic deduplication for the
##   NPB feature.
#npb_dedup_enabled: 1

############################
## Advanced Configuration ##
############################
#static_config:
  ## kubernetes-namespace，当只有一个K8s命名空间权限时，填写此值
  #kubernetes-namespace:
  ## ingress的类型，填写为kubernetes or openshift，默认kubernetes
  #ingress-flavour: kubernetes
  ## 配置后会使用配置文件中的analyzer-ip分别替换控制器下发的analyzer-ip
  #analyzer-ip: ""
  ## loglevel: "debug/info/warn/error"
  #log-level: info
  ## profiler
  #profiler: false
  ## tap—mode不是2时，afpacket-blocks是默认无效的，具体大小根据配置的MaxMemory自动适应
  ## 如果afpacket-blocks-enabled为true，afpacket-blocks有效
  #afpacket-blocks-enabled: false
  ## afpacket收包内存大小，单位是M，当ANALYZER模式或该值大于0时，使用该值
  #afpacket-blocks: 0
  ## trident-ctl listen port
  #debug-listen-port: 0
  ## packet collector and sniffer stats
  #enable-debug-stats: false
  ## analyzer模式下tap-type=3采集流量去重开关
  #analyzer-dedup-disabled: false
  ## where packet is considered to come by default if packet has no qinq with outer vlan pcp == 7
  ## ISP: 1-2,4-255, TOR: 3, default value is 3
  #default-tap-type: 3
  ## if enabled, sender can be accelerated, but
  ## only available for kernel with version >= 3.14
  ## packets sent in this mode won't able to be captured by tcpdump and trident-dump
  #enable-qos-bypass: false
  ## fastPath的map大小，设置为0时根据配置的MaxMemory自动适应
  #fast-path-map-size: 0
  ## firstPath配置值越大性能越差内存使用越小，取值范围为[1,16]，其他非法值时使用默认值8
  #first-path-level: 0
  ## receive from internal source interfaces
  ## src-interfaces will only be used with mirror-mode
  ## make sure internal interfaces have been created before running trident

  ## example:
  #src-interfaces:
  # - dummy0
  # - dummy1
  ## 是否为云网关镜像流量
  #cloud-gateway-traffic: false
  ## mirror-traffic-pcp will only be used with analyzer-mode
  #mirror-traffic-pcp: 0
  ## the size of queue linking flow generator and quadruple generator, minimum 65536:
  ##    - 1-tagged-flow-to-quadruple-generator
  ##    - 1-tagged-flow-to-app-protocol-logs
  ##    - 0-{flow_type}-{port}-packet-to-tagged-flow   ## flow_type: sflow, netflow
  #flow-queue-size: 65536
  ## the size of queue linking quadruple generator and collector, minimum 262144:
  ##    - 2-flow-with-meter-to-second-collector
  ##    - 2-flow-with-meter-to-minute-collector
  #quadruple-queue-size: 262144
  ## the size of queue linking collector and collector-sender, minimum 65536:
  ##    - 2-doc-to-collector-sender
  #collector-sender-queue-size: 65536
  ## the number of encoders for doc sender
  #collector-sender-queue-count: 1
  ## the size of queue linking flow-aggr and collector-sender, minimum 65536:
  ##    - 3-flow-to-collector-sender
  ##    - 3-protolog-to-collector-sender
  #flow-sender-queue-size: 65536
  ## the number of encoders for raw flow sender
  #flow-sender-queue-count: 1
  ## 该队列在ANALYZER模式下使用:
  ##    - 0.1-bytes-to-parse
  ##    - 0.2-packet-to-flowgenerator
  ##    - 0.3-packet-to-pipeline
  #analyzer-queue-size: 131072
  ## extra delay for second flow output
  #second-flow-extra-delay-second: 0
  #pcap:
    #enabled: false
    ## 缓冲队列长度，最小65536:
    ##    - 1-mini-meta-packet-to-pcap
    #queue-size: 65536
    ## 缓冲队列数量，[1, 16]
    #queue-count: 1
    ## 计算TCP/IP checksum，默认不计算
    #tcpip-checksum: false
    ## 单次写入文件的块大小，默认64KB
    #block-size-kb: 64
    ## 同时在写的最大pcap文件数，默认5000
    #max-concurrent-files: 5000
    ## 每个pcap文件的最大大小，默认250MB，但是1秒内即使超过该值也不会切分文件
    #max-file-size-mb: 250
    ## 所有pcap文件的最大总大小，默认100GB
    #max-directory-size-gb: 100
    ## 磁盘剩余空间不足该数值时进行删除，默认10GB
    #disk-free-space-margin-gb: 10
    ## 每个pcap文件的最大时间，默认300秒
    #max-file-period-second: 300
    ## pcap文件存储的文件夹
    #file-directory: /var/lib/pcap
    ## pcap服务器端口
    #server-port: 20205
  #flow:
    ## flow hash solts大小
    ## 由于Flow是计算的第一步，这个值也广泛用于遥测数据统计的字典哈希桶大小
    ## 包括：QuadrupleGenerator、Collector、PacketCollector
    #flow-slots-size: 131072
    ## 当前最大flow数
    #flow-count-limit: 1048576
    ## 限制每秒发送到stream的flow的最大数量，超出的随机丢弃
    #flow-sender-throttle: 1024
    ## 设置flow分钟聚合队列的长度:
    ##    - 2-second-flow-to-minute-aggrer
    #flow-aggr-queue-size: 65535
    ## 发送到collector的queue的最大flush间隔，单位为秒，可配置[1, 10]，默认为1
    #flush-interval: 1s
    ## 设置为true, 对于inport为0x30000的包,流计算不考虑mac
    #ignore-tor-mac: false
    ## 设置为true, 对于inport大于0x30000并且l2end为fasle的包,流计算不考虑mac
    #ignore-l2-end: false
    ## tcp连接状态对应的flow超时时间
    #established-timeout: 300s
    #closing-rst-timeout: 35s
    #others-timeout: 5s
  ## configuration for capture ovs-dpdk traffic
  ## use limits refer to https://dpdk-docs.readthedocs.io/en/latest/prog_guide/multi_proc_support.html
  #ovs-dpdk-enable: false
  ## use different core with primary process
  ## 0 <= dpdk-pmd-core-id <= 63
  #dpdk-pmd-core-id: 0
  #dpdk-ring-port: "dpdkr0"
  ## sflow, netflow server ports
  #xflow-collector:
    #sflow-ports:
      #- 6343
    #netflow-ports:
      #- 2055
  ## NPB VXLAN目的端口
  #vxlan-port: 4789
  ## NPB VXLAN的Flags第一个字节, 默认为0xff不支持设置为0x08, 实际的值会加上VNI的标记
  #vxlan-flags: 0xff
  ## 网包时间与当前时间相比的最大delay，单位为秒，可配置[1, 10]，默认为1
  ## 大流量下该delay可能高达近10秒
  #packet-delay: 1s
  ## 二元表配置
  #triple:
    #hash-slots-size: 65536
    #capacity: 1048576
  ## kubernetes poller类型，可选adaptive/active/passive，active表示使用setns和ip命令获取网卡，passive表示通过抓包的方式获取，adaptive表示尽可能用active
  #kubernetes-poller-type: adaptive
  ## 是否剥离ERSPAN或TEB(Transport Ethernet Bridging目前仅Vmware中使用了该协议)
  #decap-erspan: false
  ## GRPC接收缓冲大小，单位为M，默认5M
  #grpc-buffer-size: 5
  ## l7日志会话聚合的时间窗口应不小于20秒，不大于300秒. 单位为s，默认120s
  #l7-log-session-aggr-timeout: 120s
  ## 通过该脚本获取采集接口对应的MAC地址，该选项需要如下条件才能生效：
  ## 1. 采集器页面配置虚拟机MAC解析项为虚拟机XML
  ## 2. tap-mode为0
  ## 3. 接口名称和XML配置不冲突
  ## 脚本输出格式如下：
  ## tap2d283dfe,11:22:33:44:55:66
  ## tap2d283223,aa:bb:cc:dd:ee:ff
  #tap-mac-script: ""
  ## 开启后不会使用bpf过滤包
  #bpf-disabled: false
  ## 推断一个服务（vpc + ip + protocol + port）的应用层协议类型时，允许的最大连续失败次数
  ## 失败次数超过此阈值时，此服务的协议推断结果将会被记为未知，在随后的有效期内不会再进行推断
  #l7-protocol-inference-max-fail-count: 5
  ## 一个服务的应用层协议类型推断结果的有效期，单位为秒，超过有效期后会触发下一次推断
  #l7-protocol-inference-ttl: 60
  ## 流日志时序数据单个流flush最大数据长度，超过这个长度就发送到sender，单位为B，默认64B
  #packet-sequence-block-size: 64
  ## the size of queue linking packet-sequence-block and uniform-collect-sender, minimum 65536
  ## - 1-packet-sequence-block-to-uniform-collect-sender
  #packet-sequence-queue-size: 65536
  ## the number of encoders for uniform collect sender
  #packet-sequence-queue-count: 1
  ## packet-sequence-flag determines which fields need to be reported, the default value is 0, which means the feature is disabled, and 255, which means all fields need to be reported
  ## all fields corresponding to each bit:
  ## | FLAG | SEQ | ACK | PAYLOAD_SIZE | WINDOW_SIZE | OPT_MSS | OPT_WS | OPT_SACK |
  ## 8      7     6     5              4             3         2        1          0
  #packet-sequence-flag: 255
  ## 是否开启ebpf
  #ebpf-disabled: false
  ## eBPF uprobe 开启 Golang 符号表解析，默认为 false## 作用于裁剪了标准符号表的 Golang 进程（例如 K8s 自身进程一般属于此类）。
  ## 当关闭此开关时，无法采集此类进程的 uprobe 数据。
  ## 当开启此开关时，对于 Golang >= 1.13 且 < 1.18 的 Golang 进程，
  ## 将会使用 Golang 特有符号表进行解析以完成 uprobe 数据采集，但可能导致 eBPF 初始化耗时达十分钟。
  #ebpf-uprobe-golang-symbol-enabled: false
  ## 用于开启集成采集器压缩数据开关，现在仅支持 opentelemetry trace 数据压缩
  #external-agent-http-proxy-compressed: false
  ## eBPF、AF_PACKET、WINPCAP 开启的应用协议解析列表，默认包括支持的所有应用协议。
  #l7-protocol-enabled:
    #- HTTP ## for both HTTP and HTTP_TLS
    #- HTTP2 ## for HTTP2, HTTP2_TLS and gRPC
    #- Dubbo
    #- MySQL
    #- PostgreSQL
    #- Redis
    #- Kafka
    #- MQTT
    #- DNS
  ## eBPF uprobe 各项子功能生效的进程名，以正则表达式的方式配置
  #ebpf-uprobe-process-name-regexs:
    ## eBPF uprobe 开启 Golang 符号表解析的进程，默认为空表示不对任何进程开启。
    ## 作用于裁剪了标准符号表的 Golang 进程，例如 K8s 自身进程一般属于此类。
    ## 当关闭此开关时，无法采集此类进程的 uprobe 数据。
    ## 当开启此开关时，对于 Golang >= 1.13 且 < 1.18 的 Golang 进程，
    ## 将会使用 Golang 特有符号表进行解析以完成 uprobe 数据采集，但可能导致 eBPF 初始化耗时达十分钟。
    #golang-symbol: ""
    ## eBPF uprobe 开启应用协议数据采集的 Golang 进程，默认为 .* 表示对所有 Golang 进程开启。
    #golang: ".*"
    ## eBPF uprobe 开启应用协议数据采集的使用 openssl 库的进程，默认为 .* 表示对所有使用了 openssl 库的进程开启。
    #openssl: ".*"
  ## 写入单个数据文件的最大大小，单位MB
  #standalone-data-file-size: 200
  ## 写入数据文件的路径
  #standalone-data-file-dir: /var/log/deepflow-agent/
  ## 日志文件路径
  #log-file: /var/log/deepflow-agent/deepflow-agent.log
  ## 开发过程中的功能控制开关，支持多个
  #feature-flags:
  ## 协议解析的端口范围，类型map<string, string>，不配置默认全端口
  #l7-protocol-ports:
    ##协议名称: 端口范围，端口范围可以是数字或范围
    #"HTTP": "80,8080,10000-15000" # for both HTTP and HTTP_TLS
    #"HTTP2": "1-65535" # for HTTP2, HTTP2_TLS and gRPC
    #"Dubbo": "1-65535"
    #"MySQL": "1-65535"
    #"PostgreSQL": "1-65535"
    #"Redis": "1-65535"
    #"Kafka": "1-65535"
    #"MQTT": "1-65535"
    #"DNS": "53"
`)
