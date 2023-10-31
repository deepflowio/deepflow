# Field                     , DisplayName             , Unit , Description
byte                        , 字节                    , 字节 , 发送与接收字节的总和，包含从 Ether 头开始的所有内容
byte_tx                     , 发送字节                , 字节 , 发送的字节总和，包含从 Ether 头开始的所有内容 
byte_rx                     , 接收字节                , 字节 , 接受的字节总和，包含从 Ether 头开始的所有内容 
packet                      , 包数                    , 包   , 发送和接收包数的总和
packet_tx                   , 发送包数                , 包   , 发送的包数总和
packet_rx                   , 接收包数                , 包   , 接收的包数总和
l3_byte                     , 网络层载荷              , 字节 , 发送与接收字节的总和，包含 IP 头之后的总字节数
l3_byte_tx                  , 发送网络层载荷          , 字节 , 发送字节的总和，包含 IP 头之后的总字节数
l3_byte_rx                  , 接收网络层载荷          , 字节 , 接收字节的总和，包含 IP 头之后的总字节数
bpp                         , 平均包长                , 字节 , 平均包长，通过`字节 / 包数`计算得到，即 `byte / packet `
bpp_tx                      , 平均发送包长            , 字节 , 发送包的平均长度，通过`发送字节 / 发送包数`计算得到，即 `byte_tx / packet_tx `
bpp_rx                      , 平均接收包长            , 字节 , 接收包的平均长度，通过`接收字节 / 接收包数`计算得到，即 `byte_rx / packet_rx `

new_flow                    , 新建连接                , 连接 , 相比上个统计周期，新出现的连接总数，`连接`的定义详见文档
closed_flow                 , 关闭连接                , 连接 , 在当前统计周期内关闭的连接总数，`连接`的定义详见文档
flow_load                   , 活跃连接                , 连接 , 统计周期内活跃的连接数，`连接`的定义详见文档
syn_count                   , SYN 包数                , 包   , TCP 三次握手阶段 SYN 包的总数
synack_count                , SYN-ACK 包数            , 包   , TCP 三次握手阶段 SYN-ACK 包的总数
l4_byte                     , 传输层载荷              , 字节 , 发送与接收字节的总和，包含 TCP/UDP 的 payload 的长度
l4_byte_tx                  , 发送传输层载荷          , 字节 , 发送字节的总和，包含 TCP/UDP 的 payload 的长度
l4_byte_rx                  , 接收传输层载荷          , 字节 , 接收字节的总和，包含 TCP/UDP 的 payload 的长度

retrans_syn                 , SYN 重传                , 包   , TCP 三次握手阶段 SYN 包的重传次数
retrans_synack              , SYN-ACK 重传            , 包   , TCP 三次握手阶段 SYN 包的重传次数
retrans                     , TCP 重传                , 包   , TCP 包重传的次数，包含客户端和服务端重传次数
retrans_tx                  , TCP 客户端重传          , 包   , 客户端发送给服务端，TCP 包重传的次数
retrans_rx                  , TCP 服务端重传          , 包   , 客户端接收到的服务端，TCP 包重传的次数
zero_win                    , TCP 零窗                , 包   , TCP 包零窗的次数
zero_win_tx                 , TCP 客户端零窗          , 包   , 客户端发送给服务端，TCP 包零窗的次数
zero_win_rx                 , TCP 服务端零窗          , 包   , 客户端接收到的服务端，TCP 包零窗的次数
retrans_syn_ratio           , SYN 重传比例            , %    , SYN 重传比例，通过 `TCP SYN 重传 / TCP SYN 包数`计算得，即 `retrans_syn / syn_count`
retrans_synack_ratio        , SYN-ACK 重传比例        , %    , SYN-ACK 重传比例，通过 `TCP SYN-ACK 重传 / TCP SYN-ACK 包数`计算得，即 `retrans_synack / synack_count` 
retrans_ratio               , TCP 重传比例            , %    , TCP 重传比例，通过` TCP 重传 / 所有的包`计算得，即 `retrans / packet`
retrans_tx_ratio            , TCP 客户端重传比例      , %    , TCP 客户端重传比例，通过 `TCP 客户端重传 / 所有的发送包数`计算得，即 `retrans_tx / packet_tx`
retrans_rx_ratio            , TCP 服务端重传比例      , %    , TCP 服务端重传比例，通过` TCP 服务端重传 / 所有的接受包数`计算得，即 `retrans_rx /packet_rx`
zero_win_ratio              , TCP 零窗比例            , %    , TCP 零窗比例，通过` TCP 零窗比例 / 所有的包`计算得，即 `zero_win /packet`
zero_win_tx_ratio           , TCP 客户端零窗比例      , %    , TCP 客户端零窗比例，通过` TCP 客户端零窗 / 所有的发送包数`计算得，即 `zero_win_tx /packet_tx`
zero_win_rx_ratio           , TCP 服务端零窗比例      , %    , TCP 服务端零窗比例，通过` TCP 服务端零窗 / 所有的接受包数`计算得，即 `zero_win_rx /packet_rx`

tcp_establish_fail          , 建连-失败次数           , 次   , TCP 建连失败次数，建连失败场景见文档描述
client_establish_fail       , 建连-客户端失败次数     , 次   , TCP 建连过程中，客户端导致的失败次数
server_establish_fail       , 建连-服务端失败次数     , 次   , TCP 建连过程中，服务端导致的失败次数
tcp_establish_fail_ratio    , 建连-失败比例           , %    , 建连-失败比例，通过 `TCP 建连-失败次数 / 所有的关闭连接`计算得，即 `tcp_establish_fail / close_flow`
client_establish_fail_ratio , 建连-客户端失败比例     , %    , 建连-客户端失败比例，通过 `TCP 建连-客户端失败次数 / 所有的关闭连接 ` 计算得，即 `client_establish_fail / close_flow`
server_establish_fail_ratio , 建连-服务端失败比例     , %    , 建连-服务端失败比例，通过 `TCP 建连-服务端失败次数 / 所有的关闭连接` 计算得，即 `server_establish_fail / close_flow`
tcp_transfer_fail           , 传输-失败次数           , 次   , TCP 传输过程中失败的次数，传输失败场景见文档描述，包含传输和断连的所有错误
tcp_transfer_fail_ratio     , 传输-失败比例           , %    , 传输-失败比例，通过 `TCP 传输-失败次数 / 所有的关闭连接`计算得，即 `tcp_transfer_fail / close_flow`
tcp_rst_fail                , 重置次数                , 连接 , TCP 连接被 RST 的次数，包含建连、传输、断连阶段的 RST
tcp_rst_fail_ratio          , 重置比例                , %    , 重置比例，通过 `TCP 重置次数 / 所有的关闭连接` 计算得，即 `tcp_rst_fail / close_flow`
client_source_port_reuse    , 建连-客户端端口复用     , 连接 , TCP 建连失败的场景之一，见文档描述
client_syn_repeat           , 建连-客户端 SYN 结束    , 连接 , TCP 建连失败的场景之一，见文档描述
client_establish_other_rst  , 建连-客户端其他重置     , 连接 , TCP 建连失败的场景之一，见文档描述
server_syn_ack_repeat       , 建连-服务端 SYN 结束    , 连接 , TCP 建连失败的场景之一，见文档描述
server_reset                , 建连-服务端直接重置     , 连接 , TCP 建连失败的场景之一，见文档描述
server_establish_other_rst  , 建连-服务端其他重置     , 连接 , TCP 建连失败的场景之一，见文档描述
client_rst_flow             , 传输-客户端重置         , 连接 , TCP 传输失败的场景之一，见文档描述
server_rst_flow             , 传输-服务端重置         , 连接 , TCP 传输失败的场景之一，见文档描述
server_queue_lack           , 传输-服务端队列溢出     , 连接 , TCP 传输失败的场景之一，见文档描述
tcp_timeout                 , 传输-TCP 连接超时       , 连接 , TCP 传输失败的场景之一，见文档描述
client_half_close_flow      , 断连-客户端半关         , 连接 , TCP 传输失败的场景之一，见文档描述
server_half_close_flow      , 断连-服务端半关         , 连接 , TCP 传输失败的场景之一，见文档描述

rtt                         , 平均 TCP 建连时延       , 微秒 , 统计周期内，所有 TCP 建连时延的平均值，一次时延的计算见文档描述
rtt_client                  , 平均 TCP 建连客户端时延 , 微秒 , 统计周期内，所有 TCP 建连客户端时延的平均值，一次时延的计算见文档描述
rtt_server                  , 平均 TCP 建连服务端时延 , 微秒 , 统计周期内，所有 TCP 建连服务端时延的平均值，一次时延的计算见文档描述
srt                         , 平均 TCP/ICMP 系统时延  , 微秒 , 统计周期内，所有 TCP/ICMP 系统时延的平均值，一次时延的计算见文档描述
art                         , 平均数据时延            , 微秒 , 统计周期内，所有数据时延的平均值，数据时延包含 TCP/UDP，一次时延的计算见文档描述
cit                         , 平均客户端等待时延      , 微秒 , 统计周期内，所有客户端等待时延的平均值，数据时延仅包含 TCP，一次时延的计算见文档描述
rtt_max                     , 最大 TCP 建连时延       , 微秒 , 统计周期内，所有 TCP 建连时延的最大值，一次时延的计算见文档描述 
rtt_client_max              , 最大 TCP 建连客户端时延 , 微秒 , 统计周期内，所有 TCP 建连客户端时延的最大值，一次时延的计算见文档描述
rtt_server_max              , 最大 TCP 建连服务端时延 , 微秒 , 统计周期内，所有 TCP 建连服务端时延的最大值，一次时延的计算见文档描述
srt_max                     , 最大 TCP/ICMP 系统时延  , 微秒 , 统计周期内，所有 TCP/ICMP 系统时延的最大值，一次时延的计算见文档描述 
art_max                     , 最大数据时延            , 微秒 , 统计周期内，所有数据时延的最大值，数据时延包含 TCP/UDP，一次时延的计算见文档描述 
cit_max                     , 最大客户端等待时延      , 微秒 , 统计周期内，所有客户端等待时延的最大值，数据时延仅包含 TCP，一次时延的计算见文档描述 

l7_request                  , 应用请求                , 个   , 请求个数
l7_response                 , 应用响应                , 个   , 响应个数
rrt                         , 平均应用时延            , 微秒 , 统计周期内所有应用时延的平均值，一个应用时延由响应时间与请求时间的时差算得
rrt_max                     , 最大应用时延            , 微秒 , 统计周期内所有应用时延的最大值，一个应用时延由响应时间与请求时间的时差算得
l7_error                    , 应用异常                , 个   , 异常包含客户端异常 + 服务端异常，根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 response_status 字段的说明
l7_client_error             , 应用客户端异常          , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 response_status 字段的说明 
l7_server_error             , 应用服务端异常          , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 response_status 字段的说明
l7_timeout                  , 应用超时                , 个   , 未采集到响应的请求总数，不同的协议超时时间不同，例如 HTTP 默认未 1800s 
l7_error_ratio              , 应用异常比例            , %    , 异常请求的百分比，通过`异常 / 响应`计算得，即 `l7_error / l7_response`
l7_client_error_ratio       , 应用客户端异常比例      , %    , 客户端异常请求的百分比，通过`客户端异常 / 响应`计算得，即 `l7_client_error / l7_response`
l7_server_error_ratio       , 应用服务端异常比例      , %    , 客户端异常请求的百分比，通过`服务端异常 / 响应`计算得，即 `l7_server_error / l7_response`

vpc                         , VPC 个数                , 个   , 统计查看的数据中 VPC 的个数
subnet                      , 子网个数                , 个   , 统计查看的数据中子网的个数
ip                          , IP 地址个数             , 个   , 统计查看的数据中 IP 的个数
pod_cluster                 , 容器集群个数            , 个   , 统计查看的数据中容器集群的个数
pod_node                    , 容器节点个数            , 个   , 统计查看的数据中容器节点的个数
pod_ns                      , 命名空间个数            , 个   , 统计查看的数据中命名空间的个数
pod_group                   , 工作负载个数            , 个   , 统计查看的数据中工作负载的个数
pod                         , POD 个数                , 个   , 统计查看的数据中 POD 的个数
host                        , 宿主机个数              , 个   , 统计查看的数据中宿主机的个数
chost                       , 云服务器个数            , 个   , 统计查看的数据中云服务器的个数
region                      , 区域个数                , 个   , 统计查看的数据中区域的个数
az                          , 可用区个数              , 个   , 统计查看的数据中可用区的个数
ip_version                  , IP 类型                 , 个   , 统计查看的数据中 IP 类型的个数
tap_type                    , 采集点                  , 个   , 统计查看的数据中采集点的个数
vtap_id                     , 采集器                  , 个   , 统计查看的数据中采集器的个数
protocol                    , 网络协议                , 种   , 统计查看的数据中网络协议的个数
server_port                 , 服务端口                , 个   , 统计查看的数据中服务端的个数
row                         , 行数                    , 个   ,  
