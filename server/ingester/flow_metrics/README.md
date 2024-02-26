# FlowMetrics

FlowMetrics是用于接收trident包头统计数据的daemon

名字来源于"zero"的重组，念作rose，即蔷薇

# 1. 存储的所有数据

```
db                     rp            measurement   tag
--------------------------------------------------------------------------------------------------------------------
vtap_flow              rp_1m,rp_1s   main          _id,_tid,az_id,direction,host_id,ip,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_cluster_id,pod_group_id,pod_id,pod_node_id,pod_ns_id,protocol,region_id,subnet_id,capture_network_type_id,agent_id
vtap_flow_port         rp_1m,rp_1s   main          _id,_tid,az_id,direction,host_id,ip,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_cluster_id,pod_group_id,pod_id,pod_node_id,pod_ns_id,protocol,region_id,server_port,subnet_id,capture_network_type_id,agent_id
vtap_flow_edge         rp_1m,rp_1s   main          _id,_tid,az_id_0,az_id_1,host_id_0,host_id_1,ip_0,ip_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_cluster_id_0,pod_cluster_id_1,pod_group_id_0,pod_group_id_1,pod_id_0,pod_id_1,pod_node_id_0,pod_node_id_1,pod_ns_id_0,pod_ns_id_1,protocol,region_id_0,region_id_1,subnet_id_0,subnet_id_1,capture_nic,observation_point,capture_network_type_id,agent_id
vtap_flow_edge_port    rp_1m,rp_1s   main          _id,_tid,az_id_0,az_id_1,host_id_0,host_id_1,ip_0,ip_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_cluster_id_0,pod_cluster_id_1,pod_group_id_0,pod_group_id_1,pod_id_0,pod_id_1,pod_node_id_0,pod_node_id_1,pod_ns_id_0,pod_ns_id_1,protocol,region_id_0,region_id_1,server_port,subnet_id_0,subnet_id_1,capture_nic,observation_point,capture_network_type_id,agent_id

vtap_acl               rp_1m         main          _id,_tid,acl_gid,tag_type,tag_value,agent_id

vtap_wan               rp_1m         main          _id,_tid,az_id,direction,host_id,ip,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_cluster_id,pod_group_id,pod_id,pod_node_id,pod_ns_id,protocol,region_id,subnet_id,tag_type,tag_value,capture_network_type_id,agent_id
vtap_wan_port          rp_1m         main          _id,_tid,az_id,direction,host_id,ip,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_cluster_id,pod_group_id,pod_id,pod_node_id,pod_ns_id,protocol,region_id,server_port,subnet_id,tag_type,tag_value,capture_network_type_id,agent_id

vtap_packet            rp_1m,rp_1s   main          _id,_tid,az_id,direction,host_id,ip,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_cluster_id,pod_group_id,pod_id,pod_node_id,pod_ns_id,region_id,subnet_id,tag_type,tag_value,capture_network_type_id,agent_id
vtap_packet_edge       rp_1m,rp_1s   main          _id,_tid,az_id_0,az_id_1,host_id_0,host_id_1,ip_0,ip_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_cluster_id_0,pod_cluster_id_1,pod_group_id_0,pod_group_id_1,pod_id_0,pod_id_1,pod_node_id_0,pod_node_id_1,pod_ns_id_0,pod_ns_id_1,region_id_0,region_id_1,subnet_id_0,subnet_id_1,tag_type,tag_value,observation_point,capture_network_type_id,agent_id
```

`注意：所有双端（带edge的数据库）中tx、rx均是以客户端为视角的统计量`

# 2. 统计数据Tag定义

所有的表中，tag均为以下字段的组合，位置相同的字段一定同时出现。

| 名字              | 位置 | 含义                    | 类型         | 取值说明                              |
| ----------------- | ---- | ----------------------- | ------------ | ------------------------------------- |
| \_id              | N/A  | 客户端写入的shard id    | 非负整数     | u8                                    |
| \_tid             | N/A  | Trient使用的thread id   | 正整数       | u64正整数                             |
|                   |      |                         |              |                                       |
| ip_version        | 0/16 | IP地址的类型            | 正整数       | 4: IPv4                               |
|                   |      |                         |              | 6: IPv6                               |
| ip                | 0    | IP地址                  | IP字符串     | 0.0.0.0或::表示Internet               |
| group_id          | 2    | mac/ip对应的资源组ID    | 整数         | -2: Internet                          |
|                   |      |                         |              | -1: 其它                              |
|                   |      |                         |              | 0: 不可能存在                         |
|                   |      |                         |              | >=1: 资源组ID                         |
| l3_epc_id         | 4    | ip对应的EPC ID          | 整数         | -2: Internet                          |
|                   |      |                         |              | -1: 其它                              |
|                   |      |                         |              | 0: 不可能存在                         |
|                   |      |                         |              | >=1: IP对应的EPC ID                   |
|                   |      |                         |              | >=1: 由trisolaris确定含义，1表示VM    |
| l3_device_id      | 6    | ip对应的资源ID          | 非负整数     | 同l2_device_id                        |
| l3_device_type    | 6    | ip对应的资源类型        | 非负整数     | 同l2_device_type                      |
| region            | 8    | ip对应的云平台区域ID    | 非负整数     | 0: 未找到                             |
| host_id           | 9    | ip对应的宿主机ID        | 非负整数     | 0表示没找到                           |
| ip_0              | 16   | 0端IP                   | IP字符串     | 0.0.0.0或::表示Internet               |
| ip_1              | 16   | 1端IP                   | IP字符串     | 0.0.0.0或::表示Internet               |
| group_id_0        | 18   | mac_0/ip_0对应的资源组ID| 整数         | 取值范围与group_id相同                |
| group_id_1        | 18   | mac_1/ip_1对应的资源组ID| 整数         | 取值范围与group_id相同                |
| l3_epc_id_0       | 20   | ip_0对应的EPC ID        | 整数         | 取值范围与l3_epc_id相同               |
| l3_epc_id_1       | 20   | ip_1对应的EPC ID        | 整数         | 取值范围与l3_epc_id相同               |
| l3_device_id_0    | 22   | ip_0对应的资源ID        | 非负整数     | 取值范围与l3_device_id相同            |
| l3_device_type_0  | 22   | ip_0对应的资源类型      | 非负整数     | 取值范围与l3_device_type相同          |
| l3_device_id_1    | 22   | ip_1对应的资源ID        | 非负整数     | 取值范围与l3_device_id相同            |
| l3_device_type_1  | 22   | ip_1对应的资源类型      | 非负整数     | 取值范围与l3_device_type相同          |
| subnet_id_0       | 24   | ip_0对应的VL2 ID        | 非负整数     | 0表示没找到                           |
| subnet_id_1       | 24   | ip_1对应的VL2 ID        | 非负整数     | 0表示没找到                           |
| region_0          | 25   | ip_0对应的云平台区域ID  | 非负整数     | 0表示没找到                           |
| region_1          | 25   | ip_1对应的云平台区域ID  | 非负整数     | 0表示没找到                           |
| pod_node_id_0     | 26   | ip_0对应的容器节点ID    | 非负整数     | 0表示没找到                           |
| pod_node_id_1     | 26   | ip_1对应的容器节点ID    | 非负整数     | 0表示没找到                           |
| pod_group_id_0    | 26   | ip_0对应的容器组ID      | 非负整数     | 0表示没找到                           |
| pod_group_id_1    | 26   | ip_1对应的容器组ID      | 非负整数     | 0表示没找到                           |
| pod_ns_id_0       | 26   | ip_0对应的容器命名空间ID| 非负整数     | 0表示没找到                           |
| pod_ns_id_1       | 26   | ip_1对应的容器命名空间ID| 非负整数     | 0表示没找到                           |
| pod_id_0          | 26   | ip_1对应的容器ID        | 非负整数     | 0表示没找到                           |
| pod_id_1          | 26   | ip_1对应的容器ID        | 非负整数     | 0表示没找到                           |
| pod_cluster_id_0  | 26   | ip_1对应的容器集群ID    | 非负整数     | 0表示没找到                           |
| pod_cluster_id_1  | 26   | ip_1对应的容器集群ID    | 非负整数     | 0表示没找到                           |
| host_id_0         | 27   | ip_0对应的宿主机ID      | 非负整数     | 0表示没找到                           |
| host_id_1         | 27   | ip_1对应的宿主机ID      | 非负整数     | 0表示没找到                           |
| az_id_0           | 28   | ip_0对应的可用区ID      | 非负整数     | 0表示没找到                           |
| az_id_1           | 28   | ip_1对应的可用区ID      | 非负整数     | 0表示没找到                           |
|                   |      |                         |              |                                       |
| direction         | 32   | 统计量对应的流方向      | 字符串       | c2s: ip/ip_0为客户端，ip_1为服务端    |
|                   |      |                         |              | s2c: ip/ip_0为服务端，ip_1为客户端    |
| acl_gid           | 33   | ACL组ID                 | 非负整数     | 0: 未找到                             |
| protocol          | 35   | 协议                    | 非负整数     | 0: 非IP包                             |
|                   |      |                         |              | 1-255: IP protocol number             |
|                   |      |                         |              | 注意当存在server_port时仅有TCP/UDP    |
| server_port       | 36   | 服务端端口              | 非负整数     | 0-65535，0表示无L4协议号或协议号为0   |
| capture_network_type_id          | 39   | 流量采集点              | 正整数       | 1-2,4-30: 接入网络流量                |
|                   |      |                         |              | 3: 虚拟网络流量                       |
| capture_nic       | 39   | 采集网口标识            | 字符串       | 若capture_network_type_id为3: 虚拟网络流量源, 表示虚拟接口MAC地址低4字节 00000000~FFFFFFFF
|                   |      |                         |              | 其他: 接入网络流量源，表示dispatcherID: 00000000~00000000F                       |
| observation_point | 39   | 流量采集位置            | 字符串       | c: 客户端(0侧)采集                    |
|                   |      |                         |              | s: 服务端(1侧)采集                    |
| subnet_id         | 40   | ip对应的子网ID          | 非负整数     | 0: 未找到                             |
| acl_direction     | 42   | ACL匹配的方向           | 字符串       | fwd: 正向匹配                         |
|                   |      |                         |              | bwd: 反向匹配                         |
| agent_id           | 44   | 采集器控制IP的ID        | 非负整数     | 无特殊值                              |
| pod_node_id       | 45   | ip对应的容器节点ID      | 非负整数     | 0表示没找到                           |
| pod_group_id      | 45   | ip对应的容器组ID        | 非负整数     | 0表示没找到                           |
| pod_ns_id         | 45   | ip对应的容器命名空间ID  | 非负整数     | 0表示没找到                           |
| pod_id            | 26   | ip对应的容器ID          | 非负整数     | 0表示没找到                           |
| pod_cluster_id    | 26   | ip对应的容器集群ID      | 非负整数     | 0表示没找到                           |
| az_id             | 46   | ip对应的可用区ID        | 非负整数     | 0表示没找到                           |
|                   |      |                         |              |                                       |
| CODE_INDEX        | 48-53| 不能使用                | N/A          | 用于ingester标识Code的Index  |
|                   |      |                         |              |                                       |
| tag_type          | 62   | 额外的Tag类型           | 正整数       | 1: 省份（仅针对geo库）                |
|                   |      |                         |              | 2: TCP Flag（仅针对packet库）         |
|                   |      |                         |              | 3: 播送类型（仅针对packet库）         |
|                   |      |                         |              | 4: 隧道分发点ID（仅针对360库）        |
|                   |      |                         |              | 未来会扩充TTL、包长范围等字段         |
| tag_value         | 63   | tag_type对应的具体值    | 正整数/字符串| tag_type=1：字符串，大中华的省份      |
|                   |      |                         |              | tag_type=2：正整数，TCP包头的Flag字段 |
|                   |      |                         |              |   255: 其它                           |
|                   |      |                         |              |   1-31中的如下部分: 统计的TCP Flag值  |
|                   |      |                         |              |     2: SYN                            |
|                   |      |                         |              |     2+16: SYN+ACK                     |
|                   |      |                         |              |     16: ACK                           |
|                   |      |                         |              |     8+16: PSH+ACK                     |
|                   |      |                         |              |     1+16: FIN+ACK                     |
|                   |      |                         |              |     4+16: RST+ACK                     |
|                   |      |                         |              | tag_type=3：字符串，播送类性          |
|                   |      |                         |              |     broadcast: 广播                   |
|                   |      |                         |              |     multicast: 组播                   |
|                   |      |                         |              |     unicast: 未知单播                 |
|                   |      |                         |              | tag_type=4：非负整数，隧道分发点ID    |
|                   |      |                         |              |     为零时表示为PCAP策略              |

# 3. vtap_flow

存储1s、1m两种粒度的数据，统计量均以包的timestamp为准。

## 3.1. 流量

| 统计值                | 说明                                  | 时间粒度     | 单位 |
| --------------------- | ------------------------------------- | ------------ | ---- |
| packet_tx             | 累计发送总包数                        | 1m, 1s       | 个   |
| packet_rx             | 累计接收总包数                        | 1m, 1s       | 个   |
| packet                | 累计总包数                            | 1m, 1s       | 个   |
| byte_tx               | 累计发送总字节数                      | 1m, 1s       | 字节 |
| byte_rx               | 累计接收总字节数                      | 1m, 1s       | 字节 |
| byte                  | 累计总字节数                          | 1m, 1s       | 字节 |
| l3_byte_tx            | 累计发送网络层负载总字节数            | 1m, 1s       | 字节 |
| l3_byte_rx            | 累计接收网络层负载总字节数            | 1m, 1s       | 字节 |
| l4_byte_tx            | 累计发送四层负载总字节数              | 1m, 1s       | 字节 |
| l4_byte_rx            | 累计接收四层负载总字节数              | 1m, 1s       | 字节 |
| flow                  | 累计连接数                            | 1m, 1s       | 个   |
| flow_load             | 累计并发连接数                        | 1m, 1s       | 个   |
| new_flow              | 累计新建连接数，以flow.start_time为准 | 1m, 1s       | 个   |
| closed_flow           | 累计关闭连接数，以flow.start_time为准 | 1m, 1s       | 个   |
| http_request          | 累计HTTP请求包数                      | 1m, 1s       | 个   |
| http_response         | 累计HTTP响应包数                      | 1m, 1s       | 个   |
| dns_request           | 累计DNS请求包数                       | 1m, 1s       | 个   |
| dns_response          | 累计DNS响应包数                       | 1m, 1s       | 个   |

## 3.2. TCP时延

`注意`：使用时需要使用`sum/count`

`注意`：UDP请求响应时延均值复用`art`字段

| 统计值                | 说明                                  | 时间粒度     | 单位 |
| --------------------- | ------------------------------------- | ------------ | ---- |
| rtt                   | 表示建立连接RTT均值                   | 1m           | us   |
| rtt_client            | 表示客户端建立连接RTT均值             | 1m           | us   |
| rtt_server            | 表示服务端建立连接RTT均值             | 1m           | us   |
| srt                   | 表示所有系统响应时间均值              | 1m           | us   |
| art                   | 表示所有应用响应时间均值              | 1m           | us   |
| http_rrt              | 表示所有HTTP请求响应时延均值          | 1m           | us   |
| dns_rrt               | 表示所有DNS请求响应时延均值           | 1m           | us   |
| rtt_max               | 表示建立连接RTT最大值                 | 1m           | us   |
| rtt_client_max        | 表示客户端建立连接RTT最大值           | 1m           | us   |
| rtt_server_max        | 表示服务端建立连接RTT最大值           | 1m           | us   |
| srt_max               | 表示所有系统响应时间最大值            | 1m           | us   |
| art_max               | 表示所有应用响应时间最大值            | 1m           | us   |
| http_rrt_max          | 表示所有HTTP请求响应时延最大值        | 1m           | us   |
| dns_rrt_max           | 表示所有DNS请求响应时延最大值         | 1m           | us   |

## 3.3. TCP包异常

| 统计值                | 说明                                  | 时间粒度     | 单位 |
| --------------------- | ------------------------------------- | ------------ | ---- |
| retrans_tx            | 客户端累计重传次数                    | 1m           | 次   |
| retrans_rx            | 服务端累计重传次数                    | 1m           | 次   |
| retrans               | 累计重传次数                          | 1m           | 次   |
| zero_win_tx           | 客户端累计零窗次数                    | 1m           | 次   |
| zero_win_rx           | 服务端累计零窗次数                    | 1m           | 次   |
| zero_win              | 累计零窗次数                          | 1m           | 次   |

## 3.4. TCP流异常

| 统计值                  | 说明                                  | 时间粒度     | 单位 |
| ------------------------| ------------------------------------- | ------------ | ---- |
| client_rst_flow         | close_type: client other reset        | 1m, 1s       | 个   |
| server_rst_flow         | close_type: server other reset        | 1m, 1s       | 个   |
| client_syn_repeat       | close_type: client syn repeat         | 1m, 1s       | 个   |
| server_syn_ack_repeat   | close_type: server syn/ack repeat     | 1m, 1s       | 个   |
| client_half_close_flow  | close_type: client half close         | 1m, 1s       | 个   |
| server_half_close_flow  | close_type: server half close         | 1m, 1s       | 个   |
| client_source_port_reuse| close_type: client source port reuse  | 1m, 1s       | 个   |
| client_establish_other_rst| close_type: client other reset in establish stage  | 1m, 1s       | 个   |
| server_reset            | close_type: server reset              | 1m, 1s       | 个   |
| server_queue_lack       | close_type: server queue lack         | 1m, 1s       | 个   |
| server_establish_other_rst| close_type: server other reset in establish stage  | 1m, 1s       | 个   |
| tcp_timeout             | TCP连接超时次数                       | 1m, 1s       | 个   |
| client_establish_fail   | TCP客户端建连失败次数                 | 1m, 1s       | 个   |
| server_establish_fail   | TCP服务端建连失败次数                 | 1m, 1s       | 个   |
| tcp_establish_fail      | TCP建连失败次数                       | 1m, 1s       | 个   |
| http_client_error       | HTTP客户端异常次数                    | 1m, 1s       | 个   |
| http_server_error       | HTTP服务端异常次数                    | 1m, 1s       | 个   |
| http_timeout            | HTTP请求超时次数                      | 1m, 1s       | 个   |
| http_error              | HTTP异常次数                          | 1m, 1s       | 个   |
| dns_client_error        | DNS客户端错误次数                     | 1m, 1s       | 个   |
| dns_server_error        | DNS服务端错误次数                     | 1m, 1s       | 个   |
| dns_timeout             | DNS请求超时次数                       | 1m, 1s       | 个   |
| dns_error               | DNS异常次数                           | 1m, 1s       | 个   |

# 4. vtap_packet

存储1m粒度的数据，统计量均以包的timestamp为准。

## 4.1 流量

| 统计值                | 说明                                  | 时间粒度     | 单位 |
| --------------------- | ------------------------------------- | ------------ | ---- |
| packet_tx             | 累计发送总包数                        | 1m           | 个   |
| packet_rx             | 累计接收总包数                        | 1m           | 个   |
| packet                | 累计总包数                            | 1m           | 个   |
| byte_tx               | 累计发送总字节数                      | 1m           | 字节 |
| byte_rx               | 累计接收总字节数                      | 1m           | 字节 |
| byte                  | 累计总字节数                          | 1m           | 字节 |
| l3_byte_tx            | 累计发送网络层负载总字节数            | 1m, 1s       | 字节 |
| l3_byte_rx            | 累计接收网络层负载总字节数            | 1m, 1s       | 字节 |
| l4_byte_tx            | 累计发送四层负载总字节数              | 1m, 1s       | 字节 |
| l4_byte_rx            | 累计接收四层负载总字节数              | 1m, 1s       | 字节 |

## 4.2 关于cast_type

若在kvm X上某个虚拟接口上抓到 smac -> dmac 的包，那么：

- dmac是广播
  - 记录smac对应的虚拟机A及其Region/VPC/Subnet/IP（假设在kvm A上）发送的广播流量
  - 查询虚拟机A的广播流量，可能会得到2倍+的结果，当所有KVM上有2+个相同VLAN的虚接口时
  - 查询KVM A的广播流量，可能会得到2倍+的结果，当所有KVM上有2+个相同VLAN的虚接口时
- dmac是组播
  - 记录smac对应的虚拟机A及其Region/VPC/Subnet/IP（假设在kvm A上）发送的组播流量
  - 查询结果和广播一样
- dmac是未知单播
  - 在虚拟网络（tap_mode=local）环境下，如果smac、dmac均不等于抓包口的MAC
    （is_l2_end=false），记录为未知单播
- 其它情况：不统计
