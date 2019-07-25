简介
====

存储的所有数据
---------------

```
db                       measurement          tag
------------------------------------------------------------------------------------------------------------------------
df_usage_acl             TBD                  _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
df_fps_acl               TBD                  _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
 x df_flow_acl           x0000008200000000    _id,acl_gid,tap_type
 x df_flow_acl           x0000008200000001    _id,acl_gid,ip,ip_bin,ip_version,tap_type
 x df_flow_acl           x0000008a00000000    _id,acl_gid,protocol,tap_type
 x df_flow_acl           x0000008a00000001    _id,acl_gid,ip,ip_bin,ip_version,protocol,tap_type

df_usage_acl_edge        TBD                  _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
df_fps_acl_edge          TBD                  _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
 x df_flow_acl_edge      x0000008200010000    _id,acl_gid,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
 x df_flow_acl_edge      x0000008a00010000    _id,acl_gid,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,protocol,tap_type

df_usage_acl_edge_port   TBD                  _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,protocol,server_port,tap_type
 x df_flow_acl_edge_port x0000049a00010000    _id,acl_direction,acl_gid,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,protocol,server_port,tap_type

df_usage_acl_port        TBD                  _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,protocol,server_port,tap_type
 x df_flow_acl_port      x0000049a00000000    _id,acl_direction,acl_gid,protocol,server_port,tap_type
 x df_flow_acl_port      x0000049a00000001    _id,acl_direction,acl_gid,ip,ip_bin,ip_version,protocol,server_port,tap_type

df_geo_acl               x2000048300000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,isp,tap_type
 x df_geo_acl            x2000048300000000    _id,acl_direction,acl_gid,direction,isp,tap_type
df_geo_acl               x4000048300000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,region,tap_type
 x df_geo_acl            x4000048300000000    _id,acl_direction,acl_gid,direction,region,tap_type
df_geo_acl_edge          x2000048300010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,isp,tap_type
df_geo_acl_edge          x4000048300010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,region,tap_type

df_perf_acl              x0000048300000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
 x df_perf_acl           x0000048300000000    _id,acl_direction,acl_gid,direction,tap_type
df_perf_acl_edge         x0000048300010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type
df_perf_acl_edge_port    x0000049b00010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,protocol,server_port,tap_type

df_type_acl              x0000048300000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type
 x df_type_acl           x0000048300000000    _id,acl_direction,acl_gid,direction,tap_type
df_type_acl_edge         x0000048300010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type

vtap_usage               x00000160000001d1    _id,_tid,cast_type,host,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,region,subnet_id,vtap
vtap_usage               x00000908000001d1    _id,_tid,host,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,protocol,region,scope,subnet_id
vtap_usage_edge          x0000000803d10000    _id,_tid,host_0,host_1,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,l3_device_id_0,l3_device_id_1,l3_device_type_0,l3_device_type_1,l3_epc_id_0,l3_epc_id_1,protocol,region_0,region_1,subnet_id_0,subnet_id_1
vtap_usage_port          x00000110000001d1    _id,_tid,host,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,region,server_port,subnet_id
```

统计数据Tag定义
---------------

所有的表中，tag均为以下字段的组合，位置相同的字段一定同时出现。

| 名字              | 位置 | 含义                    | 格式                                  |
| ----------------- | ---- | ----------------------- | ------------------------------------- |
| \_id              | N/A  | 分析器写入的shard id    | u8数字字符串                          |
| \_tid             | N/A  | Trient使用的thread id   | u64数字字符串                         |
|                   |      |                         |                                       |
| ip_version        | 0    | IP地址类型              | 4: IPv4                               |
|                   |      |                         | 6: IPv6                               |
| ip                | 0    | IP                      | 字符串格式的IP                        |
| ip_bin            | 0    | IP                      | 二进制字符串格式的IP                  |
| mac               | 1    | MAC地址                 | 字符串格式的MAC地址 `废弃`            |
| group_id          | 2    | 资源组ID                |                                       |
| l2_epc_id         | 3    | 二层项目ID              |                                       |
| l3_epc_id         | 4    | 三层项目ID              |                                       |
| l2_device_id      | 5    | 二层设备ID              |                                       |
| l2_device_type    | 5    | 二层设备类型            | 1: 虚拟机                             |
|                   |      |                         | 3: 第三方设备                         |
|                   |      |                         | 5: 虚拟网关                           |
|                   |      |                         | 6: 服务器                             |
|                   |      |                         | 7: 网络设备                           |
|                   |      |                         | 8: 浮动IP                             |
|                   |      |                         | 9: DHCP服务                           |
| l3_device_id      | 6    | 三层设备ID              | 同上                                  |
| l3_device_type    | 6    | 三层设备类型            | 同二层设备类型                        |
| host              | 7    | 宿主机                  | 字符串格式的IP                        |
| region            | 8    | 云平台Region ID         | 字符串                                |
|                   |      |                         |                                       |
| ip_version        | 0    | IP地址类型              | 4: IPv4                               |
|                   |      |                         | 6: IPv6                               |
| ip_0              | 16   | 0端IP                   | 字符串格式的IP                        |
| ip_1              | 16   | 1端IP                   | 字符串格式的IP                        |
| ip_bin_0          | 16   | 0端IP                   | 二进制字符串格式的IP                  |
| ip_bin_1          | 16   | 1端IP                   | 二进制字符串格式的IP                  |
| mac_0             | 17   | 0端MAC                  | `废弃`                                |
| mac_1             | 17   | 1端MAC                  | `废弃`                                |
| group_id_0        | 18   |                         |                                       |
| group_id_1        | 18   |                         |                                       |
| l2_epc_id_0       | 19   |                         |                                       |
| l2_epc_id_1       | 19   |                         |                                       |
| l3_epc_id_0       | 20   |                         |                                       |
| l3_epc_id_1       | 20   |                         |                                       |
| l2_device_id_0    | 21   |                         |                                       |
| l2_device_type_0  | 21   |                         |                                       |
| l2_device_id_1    | 21   |                         |                                       |
| l2_device_type_1  | 21   |                         |                                       |
| l3_device_id_0    | 22   |                         |                                       |
| l3_device_type_0  | 22   |                         |                                       |
| l3_device_id_1    | 22   |                         |                                       |
| l3_device_type_1  | 22   |                         |                                       |
| host_0            | 23   | 宿主机                  | 源端MAC对应的宿主机                   |
| host_1            | 23   | 宿主机                  | 目的端MAC对应的宿主机                 |
| subnet_id_0       | 24   | 0侧子网ID               |                                       |
| subnet_id_1       | 24   | 1侧子网ID               |                                       |
| region_0          | 25   | 0侧云平台Region ID      |                                       |
| region_1          | 25   | 1侧云平台Region ID      |                                       |
|                   |      |                         |                                       |
| direction         | 32   | 表征流的方向            | c2s: ip/ip_0为客户端，ip_1为服务端    |
|                   |      |                         | s2c: ip/ip_0为服务端，ip_1为客户端    |
| acl_gid           | 33   | ACL组ID                 | APP策略对应的ACL组ID                  |
| vlan_id           | 34   |                         |                                       |
| protocol          | 35   | 协议                    | df\_\*, log\_\*:                      |
|                   |      |                         |   0: 非IP包                           |
|                   |      |                         |   1-255: IP protocol number           |
|                   |      |                         |   注意当存在server_port时仅有TCP/UDP  |
|                   |      |                         | vtap\_\*:                             |
|                   |      |                         |   6/17: TCP/UDP                       |
|                   |      |                         |   255: 其它                           |
| server_port       | 36   | 服务端端口              |                                       |
| cast_type         | 37   | 播送类型                | broadcast: 广播，目的MAC为广播MAC     |
|                   |      |                         | multicast: 组播，目的MAC为组播MAC     |
|                   |      |                         | unicast: 单播目的MAC，源目的至少一个为云平台MAC |
| vtap              | 38   | 采集器控制IP            | 字符串格式的IP                        |
| tap_type          | 39   | 流量采集点              | 1-2,4-30: 接入网络流量                |
|                   |      |                         | 3: 虚拟网络流量                       |
| subnet_id         | 40   | 子网ID                  |                                       |
| tcp_flags         | 41   | TCP Flags               | 255: 其它                             |
|                   |      |                         | 1-31: 统计的TCP Flags组合             |
|                   |      |                         |   2: SYN                              |
|                   |      |                         |   2+16: SYN+ACK                       |
|                   |      |                         |   16: ACK                             |
|                   |      |                         |   8+16: PSH+ACK                       |
|                   |      |                         |   1+16: FIN+ACK                       |
|                   |      |                         |   4+16: RST+ACK                       |
| acl_direction     | 42   | ACL匹配的方向           | fwd: 正向匹配                         |
|                   |      |                         | bwd: 反向匹配                         |
| scope             | 43   |                         | 1: VPC内                              |
|                   |      |                         | 2: VPC间                              |
|                   |      |                         |                                       |
| CODE_INDEX        | 48-53| 不能使用                | 用于标识Code的Index                   |
|                   |      |                         |                                       |
| isp               | 61   | 运营商（仅大中华）      | 字符串                                |
| region            | 62   | 省份（仅大中华）        | 字符串 `仅在df_geo中`                 |
| country           | 63   | 国家                    | 字符串                                |

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
- dmac是单播
  - 记录smac对应的虚拟机及其Region/VPC/Subnet/IP（假设在kvm A上）发送的单播流量
  - 记录dmac对应的虚拟机及其Region/VPC/Subnet/IP（假设在kvm B上）接收的单播流量
  - 查询虚拟机A的单播流量，会得到2倍+的结果
  - 查询虚拟机B的单播流量，会得到2倍+的结果
- 如果smac/dmac没有对应的虚拟机，此时不统计
