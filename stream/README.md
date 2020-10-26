DeepFlow stream
===============

# profiler

* 运行stream前编辑stream.yaml，修改profiler为true
* 观察堆内存：本地或远端执行`go tool pprof -inuse_space http://HOSTNAME:8002/debug/pprof/heap`
* 观察CPU：本地或远端执行`go tool pprof http://HOSTNAME:8002/debug/pprof/profile`
  - 执行top 30，可查看最热的30个函数
  - 执行list funcName，可查看某个函数的热点
  - 执行dot，可输出Graphviz源码，粘贴至 http://www.webgraphviz.com/ 可查看热点图
* 更多内容可以参考[pprof](https://golang.org/pkg/net/http/pprof/)

Flow原始数据
============================================================

索引名称表


| 索引名                    | 保留时间 (warm)  |
| - | - |
| l4_flow_log_0_*           | 1个月          |


Flow：预处理模块（DFI）通过采集网包生成双向网流（连接），实时分析模块（Poseidon）进行了部分字段的格式转换。
最终存储到Elasticsearch的原始数据，

字段列表（原则是英文命名和TSDB一致）：

| 区块     | 显示字段名           | 存储字段名      | 类型     | 索引 | 列表 | 说明                                             |
| -------- | -------------------- | ----------------| -------  | ---- | ---- | ------------------------------------------------ |
| 链路层   | 客户端MAC            | mac_0           | string   |      |      | 首包的源MAC地址                                  |
|          | 服务端MAC            | mac_1           | string   |      |      | 首包的目的MAC地址                                |
|          | 链路协议             | eth_type        | integer  | 有   |      | 以太网协议类型                                   |
|          | 客户端播送类型       | cast_types_0    | []string | 有   | 是   | 仅包含TSDB中的几个播送类型选项                   |
|          | 服务端播送类型       | cast_types_1    | []string | 有   | 是   | 仅包含TSDB中的几个播送类型选项                   |
|          | 客户端包长区间       | packet_sizes_0  | []string | 有   | 是   | 仅包含TSDB中的几个包长区间选项                   |
|          | 服务端包长区间       | packet_sizes_1  | []string | 有   | 是   | 仅包含TSDB中的几个包长区间选项                   |
|          | VLAN                 | vlan            | integer  |      |      | 网包VLAN，当该连接不同网包的VLAN不一致时取第一个 |
| 网络层   | 客户端IP             | ip_0            | ip       | 有   |      | 广域网IP为0.0.0.0或::                            |
|          | 服务端IP             | ip_1            | ip       | 有   |      | 广域网IP为0.0.0.0或::                            |
|          | 客户端真实IP         | real_ip_0       | ip       |      |      |                                                  |
|          | 服务端真实IP         | real_ip_1       | ip       |      |      |                                                  |
|          | IP类型               | ip_version      | integer  | 有   |      | 4: IPv4, 6: IPV6                                 |
|          | 网络协议             | protocol        | integer  | 有   |      | IP协议类型                                       |
|          | 隧道类型             | tunnel_type     | integer  |      |      |                                                  |
|          | 隧道ID               | tunnel_id       | integer  |      |      | 目前仅支持VXLAN，表示VNI                         |
|          | 隧道客户端IP         | tunnel_ip_0     | string   |      |      | 首包中的隧道源IP地址                             |
|          | 隧道服务端IP         | tunnel_ip_1     | string   |      |      | 首包中的隧道目的IP地址                           |
|          | 客户端TTL            | ttls_0          | []string | 有   | 是   | 仅包含TSDB中的几个TTL选项                        |
|          | 服务端TTL            | ttls_1          | []string | 有   | 是   | 仅包含TSDB中的几个TTL选项                        |
| 传输层   | 客户端口             | client_port     | integer  |      |      | 首包的源端口号                                   |
|          | 服务端口             | server_port     | integer  | 有   |      | 首包的目的端口号                                 |
|          | 客户端TCP标志位      | tcp_flags_0     | []integer| 有   | 是   | 仅包含TSDB中的几个TCP标志位选项                  |
|          | 服务端TCP标志位      | tcp_flags_1     | []integer| 有   | 是   | 仅包含TSDB中的几个TCP标志位选项                  |
|          | 客户端总TCP标志位    | tcp_flags_bit_0 | integer  |      |      |                                                  |
|          | 服务端总TCP标志位    | tcp_flags_bit_1 | integer  |      |      |                                                  |
| 应用层   | 应用协议             | l7_protocol     | string   | 有   |      | 取值HTTP、DNS、其他                              |
| 广域网   | 客户端省份           | province_0      | string   | 有   |      | 表示real_ip_0的中国省份名称                      |
|          | 服务端省份           | province_1      | string   | 有   |      | 表示real_ip_1的中国省份名称                      |
| 知识图谱 | 客户端区域           | region_id_0     | integer  | 有   |      |                                                  |
|          | 服务端区域           | region_id_1     | integer  | 有   |      |                                                  |
|          | 客户端可用区         | az_id_0         | integer  | 有   |      |                                                  |
|          | 服务端可用区         | az_id_1         | integer  | 有   |      |                                                  |
|          | 客户端宿主机         | host_id_0       | integer  | 有   |      |                                                  |
|          | 服务端宿主机         | host_id_1       | integer  | 有   |      |                                                  |
|          | 客户端设备类型       | l3_device_type_0| integer  | 有   |      | 1: 虚拟机                                        |
|          |                      |                 |          |      |      | 3：裸金属服务器                                  |
|          |                      |                 |          |      |      | 5：虚拟路由器                                    |
|          |                      |                 |          |      |      | 6：虚拟化服务器                                  |
|          |                      |                 |          |      |      | 7：网络设备                                      |
|          |                      |                 |          |      |      | 8：浮动IP地址                                    |
|          |                      |                 |          |      |      | 9：DHCP服务                                      |
|          | 服务端设备类型       | l3_device_type_1| integer  | 有   |      |                                                  |
|          | 客户端设备           | l3_device_id_0  | integer  | 有   |      |                                                  |
|          | 服务端设备           | l3_device_id_1  | integer  | 有   |      |                                                  |
|          | 客户端容器节点       | pod_node_id_0   | integer  | 有   |      |                                                  |
|          | 服务端容器节点       | pod_node_id_1   | integer  | 有   |      |                                                  |
|          | 客户端容器命名空间   | pod_ns_id_0     | integer  | 有   |      |                                                  |
|          | 服务端容器命名空间   | pod_ns_id_1     | integer  | 有   |      |                                                  |
|          | 客户端容器POD组      | pod_group_id_0  | integer  | 有   |      |                                                  |
|          | 服务端容器POD组      | pod_group_id_1  | integer  | 有   |      |                                                  |
|          | 客户端容器POD        | pod_id_0        | integer  | 有   |      |                                                  |
|          | 服务端容器POD        | pod_id_1        | integer  | 有   |      |                                                  |
|          | 客户端VPC            | l3_epc_id_0     | integer  | 有   |      |                                                  |
|          | 服务端VPC            | l3_epc_id_1     | integer  | 有   |      |                                                  |
|          | 客户端网口VPC        | epc_id_0        | integer  |      |      |                                                  |
|          | 服务端网口VPC        | epc_id_1        | integer  |      |      |                                                  |
|          | 客户端子网           | subnet_id_0     | integer  | 有   |      |                                                  |
|          | 服务端子网           | subnet_id_1     | integer  | 有   |      |                                                  |
| 流信息   | 流结束类型           | close_type      | integer  | 有   |      | 0. unknown：未知                                 |
|          |                      |                 |          |      |      | 1. tcp-fin：正常结束                             |
|          |                      |                 |          |      |      | 2. tcp-server-rst：服务端其他异常                |
|          |                      |                 |          |      |      | 3. timeout：超时                                 |
|          |                      |                 |          |      |      | 5. forced-report：强制上报                       |
|          |                      |                 |          |      |      | 7. client-syn-repeat：客户端重复SYN              |
|          |                      |                 |          |      |      | 8. server-half-close：服务端半关                 |
|          |                      |                 |          |      |      | 9. tcp-client-rst：客户端其他异常                |
|          |                      |                 |          |      |      | 10. server-syn-ack-repeat：服务端重复SYN         |
|          |                      |                 |          |      |      | 11. client-half-close：客户端半关                |
|          |                      |                 |          |      |      | 13. client-source-port-reuse：客户端端口复用     |
|          |                      |                 |          |      |      | 15. server-reset：服务端直接重置                 |
|          |                      |                 |          |      |      | 17. server-queue-lack：服务端队列不足            |
|          |                      |                 |          |      |      | 18. client-establish-other-rst：客户端建连其他重置 |
|          |                      |                 |          |      |      | 19. server-establish-other-rst：服务端建连其他重置 |
|          | 流数据来源           | flow_source     | integer  |      |      | 0 原始流量, 1 sFlow, 2 NetFlow/NetStream v5      |
|          | 流日志ID             | flow_id_str     | string   |      |      | flow_id的字符串形式，避免Elasticsearch的精度损失问题 |
|          | 采集点               | tap_type        | integer  | 有   |      | 3: 虚拟网络, 其他: 非虚拟网络                    |
|          | 采集网口标识         | tap_port        | string   |      |      | 显示为0x+固定八个字符的16进制如`0x01234567`      |
|          |                      |                 |          |      |      | 0x10000~0x1FFFF：接入网络流量源，后16位表示QinQ外层VLAN相对256的偏移量，不存在0x10003 |
|          |                      |                 |          |      |      | 0x30000：虚拟网络镜像流量源                      |
|          |                      |                 |          |      |      | 0x30001~0x3FFFF：虚拟网络采集器流量源，后16位表示虚拟接口MAC地址低2字节 |
|          | 采集器               | vtap_id         | integer  | 有   |      |                                                  |
|          | 客户端统计           | tap_side_0      | bool     | 有   |      | 等于l2_end_0 && l3_end_0                         |
|          | 服务端统计           | tap_side_1      | bool     | 有   |      | 等于l2_end_1 && l3_end_1                         |
|          | 客户端二层边界       | l2_end_0        | boolean  |      |      | 是否是源端发送网包经过的第一个采集点             |
|          | 服务端二层边界       | l2_end_1        | boolean  |      |      | 是否是目的端发送网包经过的第一个采集点           |
|          | 客户端三层边界       | l3_end_0        | boolean  |      |      | 是否是源端发送的原始网包（未经过路由）           |
|          | 服务端三层边界       | l3_end_1        | boolean  |      |      | 是否是目的端发送的原始网包（未经过路由）         |
|          | 开始时间             | start_time      | date     | 有   |      | DFI Agent第一次输出：首包时间戳                  |
|          |                      |                 |          |      |      | DFI Agent后续输出：上一次输出的end_time          |
|          | 结束时间             | end_time        | date     | 有   |      | DFI Agent输出这个连接的时间戳                    |
|          | 流持续时间           | duration        | long     |      |      |                                                  |
| 指标量   | 客户端发送包         | packet_tx       | long     |      |      |                                                  |
|          | 客户端接收包         | packet_rx       | long     |      |      |                                                  |
|          | 客户端发送字节       | byte_tx         | long     |      |      |                                                  |
|          | 客户端接收字节       | byte_rx         | long     |      |      |                                                  |
|          | 客户端发送L3载荷字节 | l3_byte_tx      | long     |      |      |                                                  |
|          | 客户端接收L3载荷字节 | l3_byte_rx      | long     |      |      |                                                  |
|          | 客户端累计发送包     | total_packet_tx | long     |      |      |                                                  |
|          | 客户端累计接收包     | total_packet_rx | long     |      |      |                                                  |
|          | 客户端累计发送字节   | total_byte_tx   | long     |      |      |                                                  |
|          | 客户端累计接收字节   | total_byte_rx   | long     |      |      |                                                  |
|          | L7请求数             | l7_request      | integer  |      |      |                                                  |
|          | L7响应数             | l7_response     | integer  |      |      |                                                  |
|          | 客户端TCP建连时延    | rtt_client      | integer  |      |      | 表示client端TCP会话三次握手阶段计算的往返时延，长流的情况下只会上报一次(可能为null) (单位：微秒) |
|          | 服务端TCP建连时延    | rtt_server      | integer  |      |      | 表示server端TCP会话三次握手阶段计算的往返时延，长流的情况下只会上报一次(可能为null) (单位：微秒) |
|          | TCP建连时延          | rtt             | integer  |      |      | 表示TCP会话三次握手阶段计算的往返时延平均值，长流的情况下只会上报一次(可能为null) (单位：微秒) |
|          | TCP系统时延          | srt             | integer  |      |      | 表示TCP会话数据传输阶段计算的往返时延平均值(可能为null)，长流的情况下表示每force_report周期内的往返时延平均值 (单位：微秒) |
|          | L4应用时延           | art             | integer  |      |      | 表示TCP连接存活时间内的应用响应时间平均值 (单位：微秒) |
|          | L7应用时延           | rrt             | integer  |      |      |                                                  |
|          | 客户端TCP重传        | retans_tx       | integer  |      |      | 长流的情况下表示每force_report周期内的重传次数   |
|          | 服务端TCP重传        | retrans_rx      | integer  |      |      |                                                  |
|          | 客户端TCP零窗        | zero_win_tx     | integer  |      |      | 长流的情况下表示每force_report周期内的零窗次数   |
|          | 服务端TCP零窗        | zero_win_rx     | integer  |      |      |                                                  |
|          | L7客户端异常请求     | l7_client_error | integer  |      |      |                                                  |
|          | L7服务端异常响应     | l7_server_error | integer  |      |      |                                                  |
|          | L7服务端超时         | l7_server_timeou| integer  |      |      |                                                  |

- 以太网协议类型: https://en.wikipedia.org/wiki/EtherType
- IPv4协议类型: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
