package example

var YamlVTapGroupConfig = []byte(`
# 资源限制
# CPU限制，单位：逻辑核，默认值: 1，值域[1, 100000]
max_cpus: 1
# 内存限制，单位：M字节，默认值: 768，值域[128, 100000]
max_memory: 768
# 系统空闲内存限制，单位：%，默认值: 10，值域[0, 100]
# 说明：系统空闲内存的最低百分比，当比例低于该值的90%时采集器将重启
sys_free_memory_limit: 100000
# 采集包限速，单位：Kpps，默认值: 200，值域[1, 1000000]
max_collect_pps: 200
# 分发流限速，单位：Mbps，默认值: 1000，值域[1, 10000]
max_npb_bps: 1000
# 分发熔断阈值，单位：Mbps，默认值: 0，值域[0, 10000]
# 说明：当分发接口出方向达到或超过阈值时将停止分发，当连续5个监控间隔低于(阈值-分发流量限制)*90%时恢复分发。注意：配置此值必须大于分发流限速，输入0表示关闭此功能。
max_tx_bandwidth: 0
# 分发熔断监控间隔，单位：秒，默认值: 10，值域[1, 60]
# 说明：分发接口出方向流量速率的监控间隔
bandwidth_probe_interval: 10
# 日志发送速率，单位：条/小时，默认值: 300，值域[0, 10000]
# 说明：设置为0表示不限速
log_threshold: 300
# 日志打印等级，默认值: INFO，可选值有：DEBUG/INFO/WARNING/ERROR
log_level: INFO
# 日志文件大小，单位：M字节，默认值：1000，值域[10, 10000]
log_file_size: 1000
# 线程数限制，单位：个，默认值：100，值域[1， 1000]
thread_threshold: 100
# 进程数限制，单位：个，默认值：10，值域[1， 100]
process_threshold: 10

# 基础配置参数
# 采集网口，默认值：^tap*，长度范围[0, 65535]
tap_interface_regex: ^tap*
# 流量过滤，默认值：空，表示全采集，长度范围[1, 512]
# 请参考BPF语法：https://biot.com/capstats/bpf.html
capture_bpf:
# 采集包长，单位：字节，默认值：65535，值域[128, 65535]
# 说明：DPDK环境目前不支持此参数
capture_packet_size: 65535
# 流量采集方式，默认值：0，表示自适应，可选值：0表示自适应/2表示AF_PACKET V2/3表示AF_PACKET V3
# 说明：Linux环境中的流量采集方式
capture_socket_type: 0
# 解封装隧道类型，默认值：0，表示无，可选值：0表示无/1表示VXLAN/2表示GRE/3表示IPIP
decap_type: 0
# 虚拟机MAC解析，默认值: 0，表示接口MAC，可选值：0表示接口MAC/1表示接口名称/2表示虚拟机XML
# 说明：KVM类型采集器获取虚拟机真实MAC地址的方式
if_mac_source: 0
# 虚拟机XML文件夹，默认值: /etc/libvirt/qemu/，长度范围[0, 100]
vm_xml_path: /etc/libvirt/qemu/
# 最长同步间隔，单位：秒，默认值：60，值域[10， 3600]
sync_interval: 60
# 最长逃逸时间，单位：秒，默认值：3600，值域[600, 2592000]
max_escape_seconds: 3600
# UDP最大MTU，单位：字节，默认值: 1500，值域[500, 10000]
mtu: 1500
# 裸UDP外层VLAN，默认值: 0，表示不带任何VLAN标签，值域[0, 4095]
output_vlan: 0
# 是否请求NAT IP，默认值：0，表示否，可选值：0表示否/1表示是
nat_ip_enabled: 0
# 日志存储时长，单位：天，默认值：30，值域[7, 365]
log_retention: 300

# 全景图配置参数
# 数据套接字，默认值: TCP，可选值：TCP/UDP
collector_socket_type: TCP
# PCAP套接字，默认值: TCP，可选值：TCP/UDP/RAW_UDP
compressor_socket_type: TCP
# HTTP日志代理客户端，默认值: X-Forwarded-For，可选值：关闭/X-Forwarded-For
http_log_proxy_client: X-Forwarded-For
# HTTP日志XRequestID，默认值: 关闭，可选值：关闭/X-Request-ID
http_log_x_request_id: 关闭
# 应用流日志TraceID，默认值: 关闭，可选值：关闭/X-B3-TraceId/uber-trace-id/sw6/sw8
http_log_trace_id: 关闭
# 应用流日志SpanID，默认值：关闭，可选值：关闭/X-B3-ParentSpanId/uber-trace-id/sw6/sw8
http_log_span_id: 关闭
# 应用日志解析包长，默认值: 256，值域[256, 1500]
# 说明：采集HTTP、DNS日志时的解析的包长，注意不要超过采集包长参数
l7_log_packet_size: 256
# 流日志采集速率，默认值: 10000，值域[100, 1000000]
# 说明：每秒采集的流日志条数，超过以后采样
l4_log_collect_nps_threshold: 10000
# 应用日志采集速率，默认值: 10000，值域[100, 1000000]
# 每秒采集的HTTP和DNS日志条数，超过时采样
l7_log_collect_nps_threshold: 10000

# 包分发配置参数
# 分发套接字，默认值: RAW_UDP，可选值：UDP/RAW_UDP
npb_socket_type: RAW_UDP
# 内层附加头，默认值: 0，表示无，可选值：0表示无/1表示802.1Q
npb_vlan_mode: 0

# 基础功能开关
# 同步资源信息，默认值: 0，表示关闭，可选值：0表示关闭/1表示开启
platform_enabled: 0
# 日志发送，默认值：1，表示开启，可选值：0表示关闭/1表示开启
rsyslog_enabled: 1
# 时钟同步，默认值：1，表示开启，可选值：0表示关闭/1表示开启
ntp_enabled: 1
# 云平台资源信息下发，默认值：0，表示全部，可选值（多选）：0表示全部/全部云平台的lcuuid（可通过命令metaflow-ctl get domain获取）
domains:
  - 0
# 容器集群内部IP下发，默认值：0，表示所有集群，可选值：0表示所有集群/1表示采集器所在集群
pod_cluster_internal_ip: 1

# 全景图功能开关
# 指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
collector_enabled: 1
# 非活跃端口指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
inactive_server_port_enabled: 1
# 网络性能指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
# 说明：关闭时，采集器仅计算最基本的网络层吞吐指标量
l4_performance_enabled: 1
# 应用性能指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
l7_metrics_enabled: 1
# 秒粒度指标数据，默认值：1，表示开启，可选值：0表示关闭/1表示开启
vtap_flow_1s_enabled: 1

# 包分发功能开关
# 全局去重，默认值：1，表示开启，可选值：0表示关闭/1表示开启
npb_dedup_enabled: 1
`)
