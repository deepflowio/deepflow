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

var YamlVTapGroupConfig = []byte(`## 采集器组ID
vtap_group_id: g-xxxxxx
## 资源限制
## CPU限制，单位：逻辑核，默认值: 1，值域[1, 100000]
#max_cpus: 1
## 内存限制，单位：M字节，默认值: 768，值域[128, 100000]
#max_memory: 768
## 系统空闲内存限制，单位：%，默认值: 10，值域[0, 100]
## 说明：系统空闲内存的最低百分比，当比例低于该值的90%时采集器将重启
#sys_free_memory_limit: 0
## 采集包限速，单位：Kpps，默认值: 200，值域[1, 1000000]
#max_collect_pps: 200
## 分发流限速，单位：Mbps，默认值: 1000，值域[1, 10000]
#max_npb_bps: 1000
## 分发熔断阈值，单位：Mbps，默认值: 0，值域[0, 10000]
## 说明：当分发接口出方向达到或超过阈值时将停止分发，当连续5个监控间隔低于(阈值-分发流量限制)*90%时恢复分发。注意：配置此值必须大于分发流限速，输入0表示关闭此功能。
#max_tx_bandwidth: 0
## 分发熔断监控间隔，单位：秒，默认值: 10，值域[1, 60]
## 说明：分发接口出方向流量速率的监控间隔
#bandwidth_probe_interval: 10
## 日志发送速率，单位：条/小时，默认值: 300，值域[0, 10000]
## 说明：设置为0表示不限速
#log_threshold: 300
## 日志打印等级，默认值: INFO，可选值有：DEBUG/INFO/WARNING/ERROR
#log_level: INFO
## 日志文件大小，单位：M字节，默认值：1000，值域[10, 10000]
#log_file_size: 1000
## 线程数限制，单位：个，默认值：500，值域[1， 1000]
#thread_threshold: 500
## 进程数限制，单位：个，默认值：10，值域[1， 100]
#process_threshold: 10
#
## 基础配置参数
## 采集网口，默认值：^(tap.*|cali.*|veth.*|eth.*|en[ospx].*|lxc.*|lo|[0-9a-f]+_h)$，长度范围[0, 65535]
## qemu: tap.*
## localhost: lo
## common nic: eth|en[ospx].*
## flannel: veth.*
## calico: cali.*
## cilium: lxc.*
## kube-ovn: [0-9a-f]+_h$#
#tap_interface_regex: ^(tap.*|cali.*|veth.*|eth.*|en[ospx].*|lxc.*|lo|[0-9a-f]+_h)$
## 流量过滤，默认值：空，表示全采集，长度范围[1, 512]
## 请参考BPF语法：https://biot.com/capstats/bpf.html
#capture_bpf:
## 采集包长，单位：字节，默认值：65535，值域[128, 65535]
## 说明：DPDK环境目前不支持此参数
#capture_packet_size: 65535
## 流量采集方式，默认值：0，表示自适应，可选值：0表示自适应/2表示AF_PACKET V2/3表示AF_PACKET V3
## 说明：Linux环境中的流量采集方式
#capture_socket_type: 0
## 解封装隧道类型，默认值：[1,3]，表示VXLAN+IPIP，可选值：0表示无/1表示VXLAN/2表示GRE/3表示IPIP
#decap_type:
#- 1
#- 3
## 虚拟机MAC解析，默认值: 0，表示接口MAC，可选值：0表示接口MAC/1表示接口名称/2表示虚拟机XML
## 说明：KVM类型采集器获取虚拟机真实MAC地址的方式
#if_mac_source: 0
## 虚拟机XML文件夹，默认值: /etc/libvirt/qemu/，长度范围[0, 100]
#vm_xml_path: /etc/libvirt/qemu/
## 最长同步间隔，单位：秒，默认值：60，值域[10， 3600]
#sync_interval: 60
## 最长逃逸时间，单位：秒，默认值：3600，值域[600, 2592000]
#max_escape_seconds: 3600
## UDP最大MTU，单位：字节，默认值: 1500，值域[500, 10000]
#mtu: 1500
## 裸UDP外层VLAN，默认值: 0，表示不带任何VLAN标签，值域[0, 4095]
#output_vlan: 0
## 是否请求NAT IP，默认值：0，表示否，可选值：0表示否/1表示是
#nat_ip_enabled: 0
## 日志存储时长，单位：天，默认值：30，值域[7, 365]
#log_retention: 300
## 控制器通信端口，默认值：30035，可选值：1-65535
#proxy_controller_port: 30035
## 数据节点通信端口，默认值：30033，可选值：1-65535
#analyzer_port: 30033
#
## 全景图配置参数
## 数据套接字，默认值: TCP，可选值：TCP/UDP/FILE
#collector_socket_type: TCP
## PCAP套接字，默认值: TCP，可选值：TCP/UDP/RAW_UDP
#compressor_socket_type: TCP
## HTTP日志代理客户端，默认值: X-Forwarded-For，可选值：关闭/X-Forwarded-For
#http_log_proxy_client: X-Forwarded-For
## HTTP日志XRequestID，默认值: 关闭，可选值：关闭/X-Request-ID
#http_log_x_request_id: X-Request-ID
## 应用流日志TraceID，默认值: traceparent,sw8，可选值：关闭/traceparent/X-B3-TraceId/uber-trace-id/sw6/sw8
## 支持输入自定义值，支持输入逗号分隔的多个值（除关闭外）
#http_log_trace_id: traceparent, sw8
## 应用流日志SpanID，默认值：traceparent,sw8，可选值：关闭/traceparent/X-B3-SpanId/uber-trace-id/sw6/sw8
## 支持输入自定义值，支持输入逗号分隔的多个值（除关闭外）
#http_log_span_id: traceparent, sw8
## 应用日志解析包长，默认值: 1024，值域[256, 1500]
## 说明：采集HTTP、DNS日志时的解析的包长，注意不要超过采集包长参数
#l7_log_packet_size: 1024
## 流日志采集速率，默认值: 10000，值域[100, 1000000]
## 说明：每秒采集的流日志条数，超过以后采样
#l4_log_collect_nps_threshold: 10000
## 应用日志采集速率，默认值: 10000，值域[100, 1000000]
## 每秒采集的HTTP和DNS日志条数，超过时采样
#l7_log_collect_nps_threshold: 10000
#
## 包分发配置参数
## 分发套接字，默认值: RAW_UDP，可选值：UDP/RAW_UDP
#npb_socket_type: RAW_UDP
## 内层附加头，默认值: 0，表示无，可选值：0表示无/1表示802.1Q
#npb_vlan_mode: 0
#
## 基础功能开关
## 同步资源信息，默认值: 0，表示关闭，可选值：0表示关闭/1表示开启
#platform_enabled: 0
## 日志发送，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#rsyslog_enabled: 1
## 时钟同步，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#ntp_enabled: 1
## 云平台资源信息下发，默认值：0，表示全部，可选值（多选）：0表示全部/全部云平台的lcuuid（可通过命令deepflow-ctl get domain获取）
#domains:
#  - 0
## 容器集群内部IP下发，默认值：0，表示所有集群，可选值：0表示所有集群/1表示采集器所在集群
#pod_cluster_internal_ip: 1
#
## 全景图功能开关
## 指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#collector_enabled: 1
## 非活跃端口指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#inactive_server_port_enabled: 1
## 非活跃IP指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#inactive_ip_enabled: 1
## 网络性能指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
## 说明：关闭时，采集器仅计算最基本的网络层吞吐指标量
#l4_performance_enabled: 1
## 应用性能指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#l7_metrics_enabled: 1
## 秒粒度指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#vtap_flow_1s_enabled: 1
## 流日志开启采集点，默认值：0，表示全部，可选值：-1表示无/0表示全部/所有采集器点的数据标记值
#l4_log_tap_types:
#  - 0
## 应用日志开启采集点，默认值：0，表示全部，可选值：-1表示无/0表示全部/所有采集器点的数据标记值
#l7_log_store_tap_types:
#  - 0
## 数据集成HTTP代理，默认值：0，表示关闭，可选址：0表示关闭/1表示开启
#external_agent_http_proxy_enabled: 0
## 数据集成HTTP代理端口，默认值：38086，可选值：1-65535
#external_agent_http_proxy_port: 38086
#
## 包分发功能开关
## 全局去重，默认值：1，表示开启，可选值：0表示关闭/1表示开启
#npb_dedup_enabled: 1
#
## 采集器静态配置
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
  ## Tap mode
  ## LOCAL:0, MIRROR/OVS-DPDK:1, ANALYZER:2
  #tap-mode: 0
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
  #external_agent_http_proxy_compressed: false
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
    #golang-symbol:
    ## eBPF uprobe 开启应用协议数据采集的 Golang 进程，默认为 .* 表示对所有 Golang 进程开启。
    #golang: .*
    ## eBPF uprobe 开启应用协议数据采集的使用 openssl 库的进程，默认为 .* 表示对所有使用了 openssl 库的进程开启。
    #openssl: .*
  ## 写入文件流日志大小，单位MB
  #standalone-data-file-size: 200
  ## 日志文件路径
  #log-file: /var/log/deepflow-agent/deepflow-agent.log
  ## 开发过程中的功能控制开关，支持多个
  #feature-flags:
`)
