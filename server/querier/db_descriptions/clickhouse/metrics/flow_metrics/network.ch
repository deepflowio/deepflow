# Field                     , DisplayName             , Unit , Description
byte                        , 字节                    , 字节 , `发送字节 + 接收字节`
byte_tx                     , 发送字节                , 字节 , 资源发送的字节数总和（含 Ethernet 头） 
byte_rx                     , 接收字节                , 字节 , 资源接收的字节数总和（含 Ethernet 头） 
packet                      , 包数                    , 包   , `发送包数 + 接收包数`
packet_tx                   , 发送包数                , 包   , 资源发送的包数总和
packet_rx                   , 接收包数                , 包   , 资源接收的包数总和
l3_byte                     , 网络层载荷              , 字节 , `发送网络层载荷 + 接收网络层载荷`
l3_byte_tx                  , 发送网络层载荷          , 字节 , 资源发送的网络层载荷字节数总和（不含 IP 头）
l3_byte_rx                  , 接收网络层载荷          , 字节 , 资源接收的网络层载荷字节数总和（不含 IP 头）
bpp                         , 平均包长                , 字节 , `字节 / 包数`
bpp_tx                      , 平均发送包长            , 字节 , `发送字节 / 发送包数`
bpp_rx                      , 平均接收包长            , 字节 , `接收字节 / 接收包数`

new_flow                    , 新建连接                , 连接 , 采集周期内新建的 TCP 连接数，`连接`的定义详见文档
closed_flow                 , 关闭连接                , 连接 , 采集周期内关闭的 TCP 连接数，`连接`的定义详见文档
flow_load                   , 活跃连接                , 连接 , 采集周期内活跃的连接数，包括有数据交互的长连接、无数据交互的长连接、周期内关闭的短连接，`连接`的定义详见文档
syn_count                   , SYN 包数                , 包   , SYN 包的总数
synack_count                , SYN-ACK 包数            , 包   , SYN-ACK 包的总数
l4_byte                     , 传输层载荷              , 字节 , `发送传输层载荷 + 接收传输层载荷`
l4_byte_tx                  , 发送传输层载荷          , 字节 , 资源发送的包传输层载荷字节数总和（不含 TCP/UDP 头）
l4_byte_rx                  , 接收传输层载荷          , 字节 , 资源接收的包传输层载荷字节数总和（不含 TCP/UDP 头）

retrans_syn                 , SYN 重传                , 包   , SYN 包的重传次数
retrans_synack              , SYN-ACK 重传            , 包   , SYN-ACK 包的重传次数
retrans                     , TCP 重传                , 包   , `TCP 客户端重传 + TCP 服务端重传`
retrans_tx                  , TCP 客户端重传          , 包   , 资源发送的 TCP 重传包次数
retrans_rx                  , TCP 服务端重传          , 包   , 资源接收的 TCP 重传包次数
zero_win                    , TCP 零窗                , 包   , `TCP 客户端零窗 + TCP 服务端零窗`
zero_win_tx                 , TCP 客户端零窗          , 包   , 资源发送的 TCP 零窗包次数
zero_win_rx                 , TCP 服务端零窗          , 包   , 资源接收的 TCP 零窗包次数
retrans_syn_ratio           , SYN 重传比例            , %    , `TCP SYN 重传 / TCP SYN 包数`
retrans_synack_ratio        , SYN-ACK 重传比例        , %    , `TCP SYN-ACK 重传 / TCP SYN-ACK 包数` 
retrans_ratio               , TCP 重传比例            , %    , `TCP 重传 /  包数`
retrans_tx_ratio            , TCP 客户端重传比例      , %    , `TCP 客户端重传 / 发送包数`
retrans_rx_ratio            , TCP 服务端重传比例      , %    , `TCP 服务端重传 / 接收包数`
zero_win_ratio              , TCP 零窗比例            , %    , `TCP 零窗 / 包数`
zero_win_tx_ratio           , TCP 客户端零窗比例      , %    , `TCP 客户端零窗 / 发送包数`
zero_win_rx_ratio           , TCP 服务端零窗比例      , %    , `TCP 服务端零窗 / 接收包数`

tcp_establish_fail          , 建连-失败次数           , 次   , `建连-客户端失败次数 + 建连-服务端失败次数`
client_establish_fail       , 建连-客户端失败次数     , 次   , `建连-客户端端口复用 + 建连-客户端其他重置 + 建连-客户端 ACK 缺失`
server_establish_fail       , 建连-服务端失败次数     , 次   , `建连-服务端 SYN 缺失 + 建连-服务端直接重置 + 建连-服务端其他重置`
tcp_establish_fail_ratio    , 建连-失败比例           , %    , `建连-失败次数 / 关闭连接`
client_establish_fail_ratio , 建连-客户端失败比例     , %    , `建连-客户端失败次数 / 关闭连接` 
server_establish_fail_ratio , 建连-服务端失败比例     , %    , `建连-服务端失败次数 / 关闭连接`
tcp_transfer_fail           , 传输-失败次数           , 次   , `传输-客户端重置 + 传输-服务端重置 + 传输-服务端队列溢出 + 传输-TCP 连接超时`
tcp_transfer_fail_ratio     , 传输-失败比例           , %    , `传输-失败次数 / 关闭连接`
tcp_rst_fail                , 重置次数                , 连接 , `建连-客户端其他重置 + 建连-服务端直接重置 + 建连-服务端其他重置 + 传输-客户端重置 + 传输-服务端重置`
tcp_rst_fail_ratio          , 重置比例                , %    , `重置次数 / 关闭连接`
client_source_port_reuse    , 建连-客户端端口复用     , 连接 , TCP 建连失败的场景之一，见文档描述
server_syn_miss             , 建连-服务端 SYN 缺失    , 连接 , TCP 建连失败的场景之一，见文档描述
client_establish_other_rst  , 建连-客户端其他重置     , 连接 , TCP 建连失败的场景之一，见文档描述
client_ack_miss             , 建连-客户端 ACK 缺失    , 连接 , TCP 建连失败的场景之一，见文档描述
server_reset                , 建连-服务端直接重置     , 连接 , TCP 建连失败的场景之一，见文档描述
server_establish_other_rst  , 建连-服务端其他重置     , 连接 , TCP 建连失败的场景之一，见文档描述
client_rst_flow             , 传输-客户端重置         , 连接 , TCP 传输失败的场景之一，见文档描述
server_rst_flow             , 传输-服务端重置         , 连接 , TCP 传输失败的场景之一，见文档描述
server_queue_lack           , 传输-服务端队列溢出     , 连接 , TCP 传输失败的场景之一，见文档描述
tcp_timeout                 , 传输-TCP 连接超时       , 连接 , TCP 传输失败的场景之一，见文档描述
client_half_close_flow      , 断连-客户端半关         , 连接 , TCP 断连异常的场景之一，见文档描述
server_half_close_flow      , 断连-服务端半关         , 连接 , TCP 断连异常的场景之一，见文档描述

rtt                         , 平均 TCP 建连时延       , 微秒 , 采集周期内，所有 TCP 建连时延的平均值，单次时延的计算见文档描述
rtt_client                  , 平均 TCP 建连客户端时延 , 微秒 , 采集周期内，所有 TCP 建连客户端时延的平均值，单次时延的计算见文档描述
rtt_server                  , 平均 TCP 建连服务端时延 , 微秒 , 采集周期内，所有 TCP 建连服务端时延的平均值，单次时延的计算见文档描述
srt                         , 平均 TCP/ICMP 系统时延  , 微秒 , 采集周期内，所有 TCP/ICMP 系统时延的平均值，单次时延的计算见文档描述
art                         , 平均数据时延            , 微秒 , 采集周期内，所有数据时延的平均值，数据时延包含 TCP/UDP，单次时延的计算见文档描述
cit                         , 平均客户端等待时延      , 微秒 , 采集周期内，所有客户端等待时延的平均值，数据时延仅包含 TCP，单次时延的计算见文档描述
rtt_max                     , 最大 TCP 建连时延       , 微秒 , 采集周期内，所有 TCP 建连时延的最大值，单次时延的计算见文档描述 
rtt_client_max              , 最大 TCP 建连客户端时延 , 微秒 , 采集周期内，所有 TCP 建连客户端时延的最大值，单次时延的计算见文档描述
rtt_server_max              , 最大 TCP 建连服务端时延 , 微秒 , 采集周期内，所有 TCP 建连服务端时延的最大值，单次时延的计算见文档描述
srt_max                     , 最大 TCP/ICMP 系统时延  , 微秒 , 采集周期内，所有 TCP/ICMP 系统时延的最大值，单次时延的计算见文档描述 
art_max                     , 最大数据时延            , 微秒 , 采集周期内，所有数据时延的最大值，数据时延包含 TCP/UDP，单次时延的计算见文档描述 
cit_max                     , 最大客户端等待时延      , 微秒 , 采集周期内，所有客户端等待时延的最大值，数据时延仅包含 TCP，单次时延的计算见文档描述 

l7_request                  , 应用请求                , 个   , 应用层协议请求次数
l7_response                 , 应用响应                , 个   , 应用层协议响应次数
rrt                         , 平均应用时延            , 微秒 , 采集周期内，所有应用时延的平均值，单次应用时延等于响应与请求的时间差
rrt_max                     , 最大应用时延            , 微秒 , 采集周期内，所有应用时延的最大值，单次应用时延等于响应与请求的时间差
l7_error                    , 应用异常                , 个   , `应用客户端异常 + 应用服务端异常`
l7_client_error             , 应用客户端异常          , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 response_status 字段的说明 
l7_server_error             , 应用服务端异常          , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 response_status 字段的说明
l7_timeout                  , 应用超时                , 个   , 应用超时的统计次数（默认配置下：TCP 类应用在 1800s 内未采集到响应，UDP 类应用在 150s 内未采集到响应）
l7_error_ratio              , 应用异常比例            , %    , `应用异常 / 应用响应`
l7_client_error_ratio       , 应用客户端异常比例      , %    , `应用客户端异常 / 应用响应`
l7_server_error_ratio       , 应用服务端异常比例      , %    , `应用服务端异常 / 应用响应`

row                         , 行数                    , 个   ,  
