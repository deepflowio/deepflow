简介
====

统计数据Tag定义
---------------

所有的表中，tag均为以下字段的组合，位置相同的字段一定同时出现。

| 名字              | 位置 | 含义                    | 格式                                  |
| ----------------- | ---- | ----------------------- | ------------------------------------- |
| ip_version        | 0    | IP地址类型              | 4: IPv4；6: IPv6                      |
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
| ip_version        | 16   | IP地址类型              | 4: IPv4；6: IPv6                      |
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
| protocol          | 35   |                         |                                       |
| server_port       | 36   | 服务端端口              |                                       |
| cast_type         | 37   | 播送类型                | broadcast: 广播，目的MAC为广播MAC     |
|                   |      |                         | multicast: 组播，目的MAC为组播MAC     |
|                   |      |                         | unicast: 单播目的MAC，源目的至少一个为云平台MAC |
| vtap              | 38   | 采集器控制IP            | 字符串格式的IP                        |
| tap_type          | 39   | 流量采集点              | 1-2,4-30: 接入网络流量                |
|                   |      |                         | 3: 虚拟网络流量                       |
| subnet_id         | 40   | 子网ID                  |                                       |
| acl_id            | 41   | ACL ID                  | `废弃`                                |
| acl_direction     | 42   | ACL匹配的方向           | fwd: 正向匹配                         |
|                   |      |                         | bwd: 反向匹配                         |
| scope             | 43   |                         | 0: 所有                               |
|                   |      |                         | 1: VPC内                              |
|                   |      |                         | 2: VPC间                              |
|                   |      |                         | 3: 子网内                             |
|                   |      |                         | 4: 子网间                             |
|                   |      |                         |                                       |
| CODE_INDEX        | 48-53| 不能使用                | 用于标识Code的Index                   |
|                   |      |                         |                                       |
| isp               | 61   | 运营商（仅大中华）      | 字符串                                |
| region            | 62   | 省份（仅大中华）        | 字符串 `仅在df_geo中`                 |
| country           | 63   | 国家                    | 字符串                                |

## 数据表Field定义

### df_usage

`废弃`

| 统计值                | 说明                         |
| --------------------- | ---------------------------- |
| sum_packet_tx         | 累计发送总包数               |
| sum_packet_rx         | 累计接收总包数               |
| sum_packet            | 累计发送和接收总包数         |
| sum_bit_tx            | 累计发送总比特数             |
| sum_bit_rx            | 累计接收总比特数             |
| sum_bit               | 累计发送和接收总比特数       |
|                       |                              |
| max_packet_tx         | 一秒发送总包数最大值         |
| max_packet_rx         | 一秒接收总包数最大值         |
| max_packet            | 一秒发送和接收总包数最大值   |
| max_bit_tx            | 一秒发送总比特数最大值       |
| max_bit_rx            | 一秒接收总比特数最大值       |
| max_bit               | 一秒发送和接收总比特数最大值 |

### df_fps

`废弃`

| 统计值                    | 说明                                        |
| ------------------------- | ------------------------------------------- |
| sum_flow_count            | 累计连接数                                  |
| sum_new_flow_count        | 累计新建连接数，以start_time为准            |
| sum_closed_flow_count     | 累计关闭连接数，以end_time为准              |
|                           |                                             |
| max_flow_count            | 一秒并发连接数最大值                        |
| max_new_flow_count        | 一秒新建连接数最大值                        |

### df_flow

| 统计值                    | 说明                                        |
| ------------------------- | ------------------------------------------- |
| sum_packet_tx             | 累计发送总包数，以end_time为准              |
| sum_packet_rx             | 累计接收总包数，以end_time为准              |
| sum_packet                | 累计发送和接收总包数，以end_time为准        |
| sum_bit_tx                | 累计发送总比特数，以end_time为准            |
| sum_bit_rx                | 累计接收总比特数，以end_time为准            |
| sum_bit                   | 累计发送和接收总比特数，以end_time为准      |
|                           |                                             |
| sum_flow_count            | 累计连接数，以end_time为准                  |
| sum_new_flow_count        | 累计新建连接数，以`end_time`为准            |
| sum_closed_flow_count     | 累计关闭连接数，以end_time为准              |
| sum_flow_duration         | 累计连接持续时长(us)，以end_time为准        |
| sum_closed_flow_duration  | 累计已关闭连接持续时长(us)，以end_time为准  |

### df_type

| 统计值                                   | 说明                             |
| ---------------------------------------- | -------------------------------- |
| sum_count_t_c_rst                        | close_type: client reset         |
| sum_count_t_c_half_open                  | close_type: client half open     |
| sum_count_t_c_half_close                 | close_type: client half close    |
| sum_count_t_s_rst                        | close_type: server reset         |
| sum_count_t_s_half_open                  | close_type: server half open     |
| sum_count_t_s_half_close                 | close_type: server half close    |

### df_perf

| 统计值                   | 说明                                                    |
| ------------------------ | ------------------------------------------------------- |
| sum_flow_count           | 累计连接数，`仅用于计算流重传率`                        |
| sum_closed_flow_count    | 累计结束的连接数，`仅用于计算流重传率`                  |
| sum_retrans_flow_count   | 累计重传连接数                                          |
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
| sum_art_avg              | 表示所有应用响应时间(us，可能为null)                    |
| sum_art_avg_flow         | 表示记录art_avg的flow数量                               |
|                          |                                                         |
| sum_zero_wnd_cnt_tx      | 发送方向累计零窗次数                                    |
| sum_zero_wnd_cnt_rx      | 接收方向累计零窗次数                                    |
|                          |                                                         |
| max_rtt_syn              | 所有Flow中TCP会话三次握手阶段RTT最大值(可能为null)      |
| max_rtt_avg              | 所有Flow中TCP会话存活阶段RTT平均值的最大值(可能为null)  |
|                          |                                                         |
| min_rtt_syn `TBD`        | 所有Flow中TCP会话三次握手阶段RTT最小值(可能为null)      |
| min_rtt_avg `TBD`        | 所有Flow中TCP会话存活阶段RTT平均值的最小值(可能为null)  |

### df_geo

| 统计值                   | 说明                                     |
| ------------------------ | ---------------------------------------- |
| sum_closed_flow_count    | 累计结束连接数                           |
| sum_abnormal_flow_count  | 异常网流总数：已结束但没有正常FIN的TCP   |
| sum_closed_flow_duration | 已关闭的网流的累积持续时间(us)           |
| sum_packet_tx            | 累计发送总包数                           |
| sum_packet_rx            | 累计接收总包数                           |
| sum_bit_tx               | 累计发送总字节数                         |
| sum_bit_rx               | 累计接收总字节数                         |

### df_console_log

`废弃`

仅计算同时满足如下条件的Flow：
- TCP Flow
- 结束的Flow：close_type != 5 `增加了这个条件，与5.4.0不同`
- 服务端端口号port_dst为22/23/3389之一

#### Tag组合

- tap_type, epc_0, epc_1, ip_0, ip_1, server_port, direction=c2s

#### Field列表

| 统计值                   | 说明                           |
| ------------------------ | ------------------------------ |
| sum_packet_tx            | 累计发送总包数                 |
| sum_packet_rx            | 累计接收总包数                 |
| sum_closed_flow_count    | 累计关闭连接数                 |
| sum_closed_flow_duration | 已关闭的网流的累积持续时间(us) |

### log_usage

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
