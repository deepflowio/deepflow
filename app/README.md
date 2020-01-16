简介
====


存储的所有数据
---------------

```
db                       measurement       tag
------------------------------------------------------------------------------------------------------------------------
df_usage_acl             mini              _id,acl_direction,acl_gid,direction
df_usage_acl             main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
df_usage_acl_edge        main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
df_usage_acl_edge_port   main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,protocol,server_port,tap_type
df_usage_acl_port        main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,protocol,server_port,tap_type

df_fps_acl               mini              _id,acl_direction,acl_gid,direction
df_fps_acl               main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
df_fps_acl_port          main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type,protocol,server_port
df_fps_acl_edge          main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
df_fps_acl_edge_port     main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type,protocol,server_port

df_geo_acl               main_isp          _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,isp,tap_type
df_geo_acl               main_region       _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,region,tap_type
df_geo_acl_port          main_isp          _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,isp,tap_type,protocol,server_port
df_geo_acl_port          main_region       _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,region,tap_type,protocol,server_port
df_geo_acl_edge          main_isp          _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,isp,tap_type
df_geo_acl_edge          main_region       _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,region,tap_type
df_geo_acl_edge_port     main_isp          _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,isp,tap_type,protocol,server_port
df_geo_acl_edge_port     main_region       _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,region,tap_type,protocol,server_port

df_perf_acl              mini              _id,acl_direction,acl_gid,direction
df_perf_acl              main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
df_perf_acl_port         main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type,protocol,server_port
df_perf_acl_edge         main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
df_perf_acl_edge_port    main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,protocol,server_port,tap_type

df_type_acl              main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
df_type_acl_port         main              _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type,protocol,server_port
df_type_acl_edge         main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
df_type_acl_edge_port    main              _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type,protocol,server_port

vtap_usage               main              _id,_tid,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,protocol,region,subnet_id,tap_type,vtap_id
vtap_usage               main_cast_type    _id,_tid,cast_type,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,region,subnet_id,tap_type,vtap_id
vtap_usage               main_tcp_flags    _id,_tid,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,region,subnet_id,tap_type,tcp_flags,vtap_id
vtap_usage_edge          main              _id,_tid,host,host_id_0,host_id_1,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_node_id_0,pod_node_id_1,protocol,region_0,region_1,subnet_id_0,subnet_id_1,tap_type,vtap_id
vtap_usage_port          main              _id,_tid,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,region,server_port,subnet_id,tap_type,vtap_id

vtap_flow_usage          main              _id,_tid,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,protocol,region,subnet_id,tap_type,vtap_id
vtap_flow_usage_edge     main              _id,_tid,host_0,host_1,host_id_0,host_id_1,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_node_id_0,pod_node_id_1,protocol,region_0,region_1,subnet_id_0,subnet_id_1,tap_type,vtap_id

vtap_flow_fps            main              _id,_tid,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,protocol,region,subnet_id,tap_type,vtap_id
vtap_flow_fps_edge       main              _id,_tid,host_0,host_1,host_id_0,host_id_1,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_node_id_0,pod_node_id_1,protocol,region_0,region_1,subnet_id_0,subnet_id_1,tap_type,vtap_id

vtap_flow_perf          main              _id,_tid,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,protocol,region,subnet_id,tap_type,vtap_id
vtap_flow_perf_edge     main              _id,_tid,host_0,host_1,host_id_0,host_id_1,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_node_id_0,pod_node_id_1,protocol,region_0,region_1,subnet_id_0,subnet_id_1,tap_type,vtap_id

vtap_flow_type          main              _id,_tid,host,host_id,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,pod_node_id,protocol,region,subnet_id,tap_type,vtap_id
vtap_flow_type_edge     main              _id,_tid,host_0,host_1,host_id_0,host_id_1,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,pod_node_id_0,pod_node_id_1,protocol,region_0,region_1,subnet_id_0,subnet_id_1,tap_type,vtap_id

log_usage_edge_port      main              _id,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,l3_epc_id_0,l3_epc_id_1,protocol,server_port,tap_type
```

统计数据Tag定义
---------------

所有的表中，tag均为以下字段的组合，位置相同的字段一定同时出现。

| 名字              | 位置 | 含义                    | 类型         | 取值说明                              |
| ----------------- | ---- | ----------------------- | ------------ | ------------------------------------- |
| \_id              | N/A  | 客户端写入的shard id    | 非负整数     | u8                                    |
| \_tid             | N/A  | Trient使用的thread id   | 正整数       | u64正整数                             |
|                   |      |                         |              |                                       |
| ip_version        | 0/16 | IP地址的类型            | 正整数       | 4: IPv4                               |
|                   |      |                         |              | 6: IPv6                               |
| ip                | 0    | IP地址                  | IP字符串     | 0.0.0.0或::表示Internet               |
| ip_bin            | 0    | IP地址                  | 二进制字符串 | 长度为IPv4 32或IPv6 128，值等价于ip   |
| mac               | 1    | MAC地址                 | MAC字符串    | `废弃`                                |
| group_id          | 2    | mac/ip对应的资源组ID    | 整数         | -2: Internet                          |
|                   |      |                         |              | -1: 其它                              |
|                   |      |                         |              | 0: 不可能存在                         |
|                   |      |                         |              | >=1: 资源组ID                         |
| l2_epc_id         | 3    | mac对应的EPC ID         | 整数         | `废弃`                                |
| l3_epc_id         | 4    | ip对应的EPC ID          | 整数         | -2: Internet                          |
|                   |      |                         |              | -1: 其它                              |
|                   |      |                         |              | 0: 不可能存在                         |
|                   |      |                         |              | >=1: IP对应的EPC ID                   |
| l2_device_id      | 5    | mac对应的资源ID         | 非负整数     | 0: 未找到 `废弃`                      |
| l2_device_type    | 5    | mac对应的资源类型       | 非负整数     | `废弃`                                |
|                   |      |                         |              | 0: 未找到                             |
|                   |      |                         |              | >=1: 由trisolaris确定含义，1表示VM    |
| l3_device_id      | 6    | ip对应的资源ID          | 非负整数     | 同l2_device_id                        |
| l3_device_type    | 6    | ip对应的资源类型        | 非负整数     | 同l2_device_type                      |
| host              | 7    | ip对应的宿主机          | IP字符串     | 0.0.0.0或::表示未找到 `废弃`          |
| region            | 8    | ip对应的云平台区域ID    | 非负整数     | 0: 未找到                             |
| host_id           | 9    | ip对应的宿主机ID        | 正整数       | 0表示没找到                           |
|                   |      |                         |              |                                       |
| ip_0              | 16   | 0端IP                   | IP字符串     | 0.0.0.0或::表示Internet               |
| ip_1              | 16   | 1端IP                   | IP字符串     | 0.0.0.0或::表示Internet               |
| ip_bin_0          | 16   | 0端IP                   | 二进制字符串 | 长度为IPv4 32或IPv6 128，值等价于ip_0 |
| ip_bin_1          | 16   | 1端IP                   | 二进制字符串 | 长度为IPv4 32或IPv6 128，值等价于ip_1 |
| mac_0             | 17   | 0端MAC                  | MAC字符串    | `废弃`                                |
| mac_1             | 17   | 1端MAC                  | MAC字符串    | `废弃`                                |
| group_id_0        | 18   | mac_0/ip_0对应的资源组ID| 整数         | 取值范围与group_id相同                |
| group_id_1        | 18   | mac_1/ip_1对应的资源组ID| 整数         | 取值范围与group_id相同                |
| l2_epc_id_0       | 19   | mac_0对应的EPC ID       | 整数         | `废弃`                                |
| l2_epc_id_1       | 19   | mac_1对应的EPC ID       | 整数         | `废弃`                                |
| l3_epc_id_0       | 20   | ip_0对应的EPC ID        | 整数         | 取值范围与l3_epc_id相同               |
| l3_epc_id_1       | 20   | ip_1对应的EPC ID        | 整数         | 取值范围与l3_epc_id相同               |
| l2_device_id_0    | 21   | mac_0对应的资源ID       | 非负整数     | `废弃`                                |
| l2_device_type_0  | 21   | mac_0对应的资源类型     | 非负整数     | `废弃`                                |
| l2_device_id_1    | 21   | mac_1对应的资源ID       | 非负整数     | `废弃`                                |
| l2_device_type_1  | 21   | mac_1对应的资源类型     | 非负整数     | `废弃`                                |
| l3_device_id_0    | 22   | ip_0对应的资源ID        | 非负整数     | 取值范围与l3_device_id相同            |
| l3_device_type_0  | 22   | ip_0对应的资源类型      | 非负整数     | 取值范围与l3_device_type相同          |
| l3_device_id_1    | 22   | ip_1对应的资源ID        | 非负整数     | 取值范围与l3_device_id相同            |
| l3_device_type_1  | 22   | ip_1对应的资源类型      | 非负整数     | 取值范围与l3_device_type相同          |
| host_0            | 23   | ip_0对应的宿主机        | IP字符串     | 0.0.0.0表示没找到 `废弃`              |
| host_1            | 23   | ip_1对应的宿主机        | IP字符串     | 0.0.0.0表示没找到 `废弃`              |
| subnet_id_0       | 24   | ip_0对应的VL2 ID        | 非负整数     | 0表示没找到                           |
| subnet_id_1       | 24   | ip_1对应的VL2 ID        | 非负整数     | 0表示没找到                           |
| region_0          | 25   | ip_0对应的云平台区域ID  | 非负整数     | 0表示没找到                           |
| region_1          | 25   | ip_1对应的云平台区域ID  | 非负整数     | 0表示没找到                           |
| pod_node_id_0     | 27   | ip_0对应的容器节点ID    | 正整数       | 0表示没找到                           |
| pod_node_id_1     | 27   | ip_1对应的容器节点ID    | 正整数       | 0表示没找到                           |
| host_id_0         | 28   | ip_0对应的宿主机ID      | 正整数       | 0表示没找到                           |
| host_id_1         | 28   | ip_1对应的宿主机ID      | 正整数       | 0表示没找到                           |
|                   |      |                         |              |                                       |
| direction         | 32   | 统计量对应的流方向      | 字符串       | c2s: ip/ip_0为客户端，ip_1为服务端    |
|                   |      |                         |              | s2c: ip/ip_0为服务端，ip_1为客户端    |
| acl_gid           | 33   | ACL组ID                 | 非负整数     | 0: 未找到                             |
| vlan_id           | 34   | VLAN标签                | 非负整数     | `弃用`                                |
| protocol          | 35   | 协议                    | 非负整数     | 0: 非IP包                             |
|                   |      |                         |              | 1-255: IP protocol number             |
|                   |      |                         |              | 注意当存在server_port时仅有TCP/UDP    |
| server_port       | 36   | 服务端端口              | 非负整数     | 0-65535，0表示无L4协议号或协议号为0   |
| cast_type         | 37   | 播送类型                | 字符串       | broadcast: 广播，目的MAC为广播MAC     |
|                   |      |                         |              | multicast: 组播，目的MAC为组播MAC     |
| vtap              | 38   | 采集器控制IP            | IP字符串     | 无特殊值 `废弃`                       |
| tap_type          | 39   | 流量采集点              | 正整数       | 1-2,4-30: 接入网络流量                |
|                   |      |                         |              | 3: 虚拟网络流量                       |
| subnet_id         | 40   | ip对应的子网ID          | 非负整数     | 0: 未找到                             |
| tcp_flags         | 41   | TCP Flags               | 非负整数     | 255: 其它                             |
|                   |      |                         |              | 1-31中的如下部分: 统计的TCP Flags组合 |
|                   |      |                         |              |   2: SYN                              |
|                   |      |                         |              |   2+16: SYN+ACK                       |
|                   |      |                         |              |   16: ACK                             |
|                   |      |                         |              |   8+16: PSH+ACK                       |
|                   |      |                         |              |   1+16: FIN+ACK                       |
|                   |      |                         |              |   4+16: RST+ACK                       |
| acl_direction     | 42   | ACL匹配的方向           | 字符串       | fwd: 正向匹配                         |
|                   |      |                         |              | bwd: 反向匹配                         |
| scope             | 43   | 源和目的构成的范围      | 正整数       | `废弃`                                |
|                   |      |                         |              | 1: VPC内                              |
|                   |      |                         |              | 2: VPC间                              |
| vtap_id           | 44   | 采集器控制IP的ID        | 正整数       | 无特殊值                              |
| pod_node_id       | 45   | ip对应的容器节点ID      | 正整数       | 0表示没找到                           |
|                   |      |                         |              |                                       |
| CODE_INDEX        | 48-53| 不能使用                | N/A          | 用于droplet/roze/zero标识Code的Index  |
|                   |      |                         |              |                                       |
| isp               | 61   | 运营商（仅大中华）      | 字符串       |                                       |
| region            | 62   | 省份名前缀（仅大中华）  | 字符串       | `注意：仅含两个汉字，例如黑龙`        |
| country           | 63   | 国家三位字符编码        | 字符串       | `注意：使用三位字母编码`              |

## 数据表Field定义

### df_usage

存储1s、1m两种粒度的数据，统计量均以包的timestamp为准。

| 统计值                | 说明                         |
| --------------------- | ---------------------------- |
| sum_packet_tx         | 累计发送总包数               |
| sum_packet_rx         | 累计接收总包数               |
| sum_bit_tx            | 累计发送总比特数             |
| sum_bit_rx            | 累计接收总比特数             |

### df_fps

存储1s、1m两种粒度的数据。

| 统计值                    | 说明                                        |
| ------------------------- | ------------------------------------------- |
| sum_flow_count            | 累计连接，覆盖flow生命周期内所有秒          |
| sum_new_flow_count        | 累计新建连接数，以flow.start_time为准       |
| sum_closed_flow_count     | 累计关闭连接数，以flow.end_time为准         |

### df_flow

`废弃`

存储1m粒度的数据，统计量均以`RountToMinute(flow.start_time)`为准。

| 统计值                    | 说明                                        |
| ------------------------- | ------------------------------------------- |
| sum_packet_tx             | 累计发送总包数                              |
| sum_packet_rx             | 累计接收总包数                              |
| sum_bit_tx                | 累计发送总比特数                            |
| sum_bit_rx                | 累计接收总比特数                            |
|                           |                                             |
| sum_flow_count            | 累计连接数                                  |
| sum_new_flow_count        | 累计新建连接数                              |
| sum_closed_flow_count     | 累计关闭连接数                              |
| sum_flow_duration         | 累计连接持续时长(us)                        |
| sum_closed_flow_duration  | 累计已关闭连接持续时长(us)                  |

### df_type

存储1m粒度的数据，统计量均以`RountToMinute(flow.start_time)`为准。

| 统计值                                   | 说明                             |
| ---------------------------------------- | -------------------------------- |
| sum_count_t_c_rst                        | close_type: client reset         |
| sum_count_t_c_half_open                  | close_type: client half open     |
| sum_count_t_c_half_close                 | close_type: client half close    |
| sum_count_t_s_rst                        | close_type: server reset         |
| sum_count_t_s_half_open                  | close_type: server half open     |
| sum_count_t_s_half_close                 | close_type: server half close    |

### df_perf

存储1m粒度的数据，统计量均以`RountToMinute(flow.start_time)`为准。

| 统计值                   | 说明                                                    |
| ------------------------ | ------------------------------------------------------- |
| sum_flow_count           | 累计连接数                                              |
| sum_new_flow_count       | 累计新建连接数                                          |
| sum_closed_flow_count    | 累计结束的连接数                                        |
| sum_half_open_flow_count | 累计半开连接数，用于计算建立连接成功率                  |
| sum_packet_tx            | 发送方向累计包数，`仅用于计算包重传率`                  |
| sum_packet_rx            | 接收方向累计包数，`仅用于计算包重传率`                  |
| sum_retrans_cnt_tx       | 发送方向累计重传次数                                    |
| sum_retrans_cnt_rx       | 接收方向累计重传次数                                    |
|                          |                                                         |
| sum_rtt_syn              | 表示所有建立连接RTT延迟 (us，可能为null)                |
| sum_rtt_syn_flow         | 表示记录rtt_syn的flow数量                               |
| sum_rtt_avg              | 表示所有系统响应时间 (us，可能为null)                   |
| sum_rtt_avg_flow         | 表示记录rtt的flow数量                                   |
| sum_art_avg              | 表示所有应用响应时间 (us，可能为null)                   |
| sum_art_avg_flow         | 表示记录art_avg的flow数量                               |
|                          |                                                         |
| sum_zero_wnd_cnt_tx      | 发送方向累计零窗次数                                    |
| sum_zero_wnd_cnt_rx      | 接收方向累计零窗次数                                    |
|                          |                                                         |
| max_rtt_syn              | 所有Flow中TCP会话三次握手阶段RTT最大值(可能为null)      |
| max_rtt_avg              | 所有Flow中TCP会话存活阶段RTT平均值的最大值(可能为null)  |
| max_art_avg              | 所有Flow中所有应用响应时间的最大值(可能为null)          |
| max_rtt_syn_client       | 客户端所有Flow中TCP会话三次握手阶段RTT最大值(可能为null)|
| max_rtt_syn_server       | 服务端所有Flow中TCP会话三次握手阶段RTT最大值(可能为null)|

### df_geo

存储1m粒度的数据，统计量均以`RountToMinute(flow.start_time)`为准。

| 统计值                   | 说明                                     |
| ------------------------ | ---------------------------------------- |
| sum_packet_tx            | 累计发送总包数                           |
| sum_packet_rx            | 累计接收总包数                           |
| sum_bit_tx               | 累计发送总字节数                         |
| sum_bit_rx               | 累计接收总字节数                         |
| max_rtt_syn_client       | 客户端所有Flow中TCP会话三次握手阶段RTT最大值(可能为null)|
| sum_rtt_syn_client_flow  | 表示记录客户端rtt_syn的flow数量          |

### log_usage

存储10m粒度的数据，统计量均以`RountToMinute(flow.start_time)`为准。

#### Tag组合

- ip_0, ip_1, l3_epc_id_0, l3_epc_id_1, protocol, server_port, tap_type

#### Field列表

| 统计值                   | 说明                           |
| ------------------------ | ------------------------------ |
| sum_packet_tx            | 累计发送总包数                 |
| sum_packet_rx            | 累计接收总包数                 |
| sum_bit_tx               | 累计发送总比特数               |
| sum_bit_rx               | 累计接收总比特数               |

### vtap_usage

存储1s粒度的数据，统计量均以包的timestamp为准。

#### cast_type

若在kvm X上某个虚拟接口上抓到 smac -> dmac 的包，那么：

- dmac是广播
  - 记录smac对应的虚拟机A及其Region/VPC/Subnet/IP（假设在kvm A上）发送的广播流量
  - 查询虚拟机A的广播流量，可能会得到2倍+的结果，当所有KVM上有2+个相同VLAN的虚接口时
  - 查询KVM A的广播流量，可能会得到2倍+的结果，当所有KVM上有2+个相同VLAN的虚接口时
- dmac是组播
  - 记录smac对应的虚拟机A及其Region/VPC/Subnet/IP（假设在kvm A上）发送的组播流量
  - 查询结果和广播一样
- 如果smac没有对应的虚拟机，此时不统计
