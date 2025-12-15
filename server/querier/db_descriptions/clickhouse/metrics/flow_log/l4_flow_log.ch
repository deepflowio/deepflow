# Field                     , DisplayName             , Unit , Description
byte                        , 字节                    , 字节 , 
byte_tx                     , 发送字节                , 字节 , 客户端发往服务端的字节数总和（含 Ethernet 头）
byte_rx                     , 接收字节                , 字节 , 服务端发往客户端的字节数总和（含 Ethernet 头）
total_byte_tx               , 累计发送字节            , 字节 ,
total_byte_rx               , 累计接收字节            , 字节 ,
packet                      , 包数                    , 包   , 
packet_tx                   , 发送包数                , 包   , 客户端发往服务端的包数总和
packet_rx                   , 接收包数                , 包   , 服务端发往客户端的包数总和
total_packet_tx             , 累计发送包数            , 包  ,
total_packet_rx             , 累计接收包数            , 包  ,
l3_byte                     , 网络层载荷              , 字节 , 
l3_byte_tx                  , 发送网络层载荷          , 字节 , 客户端发往服务端的网络层载荷字节数总和（不含 IP 头）
l3_byte_rx                  , 接收网络层载荷          , 字节 , 服务端发往客户端的网络层载荷字节数总和（不含 IP 头）
bpp                         , 平均包长                , 字节 , 
bpp_tx                      , 平均发送包长            , 字节 , 
bpp_rx                      , 平均接收包长            , 字节 , 

new_flow                    , 新建连接                , 连接 , 
closed_flow                 , 关闭连接                , 连接 , 
syn_count                   , SYN 包数                , 包   , SYN 包的总数
synack_count                , SYN-ACK 包数            , 包   , SYN-ACK 包的总数
l4_byte                     , 传输层载荷              , 字节 , 
l4_byte_tx                  , 发送传输层载荷          , 字节 , 客户端发往服务端的包传输层载荷字节数总和（不含 TCP/UDP 头）
l4_byte_rx                  , 接收传输层载荷          , 字节 , 服务端发往客户端的包传输层载荷字节数总和（不含 TCP/UDP 头）
direction_score             , 方向得分                ,      , 算法推理传输层连接方向（客户端、服务端角色）的准确性得分值，得分越高连接方向的准确性越高，得分最高 255
log_count                   , 日志总量                , 个   , 
fin_count                   , TCP FIN 包数            , 包   ,

retrans_syn                 , SYN 重传                , 包   , SYN 包的重传次数
retrans_synack              , SYN-ACK 重传            , 包   , SYN-ACK 包的重传次数
retrans                     , TCP 重传                , 包   , 
retrans_tx                  , TCP 客户端重传          , 包   , TCP 连接客户端发往服务端的重传包次数
retrans_rx                  , TCP 服务端重传          , 包   , TCP 连接服务端发往客户端的重传包次数
zero_win                    , TCP 零窗                , 包   , 
zero_win_tx                 , TCP 客户端零窗          , 包   , TCP 连接客户端发往服务端的零窗包次数
zero_win_rx                 , TCP 服务端零窗          , 包   , TCP 连接服务端发往客户端的零窗包次数
retrans_syn_ratio           , SYN 重传比例            , %    ,
retrans_synack_ratio        , SYN-ACK 重传比例        , %    ,
retrans_ratio               , TCP 重传比例            , %    ,
retrans_tx_ratio            , TCP 客户端重传比例      , %    ,
retrans_rx_ratio            , TCP 服务端重传比例      , %    ,
zero_win_ratio              , TCP 零窗比例            , %    ,
zero_win_tx_ratio           , TCP 客户端零窗比例      , %    ,
zero_win_rx_ratio           , TCP 服务端零窗比例      , %    ,

tcp_establish_fail          , 建连-失败次数           , 次   ,
client_establish_fail       , 建连-客户端失败次数     , 次   ,
server_establish_fail       , 建连-服务端失败次数     , 次   ,
tcp_establish_fail_ratio    , 建连-失败比例           , %    ,
client_establish_fail_ratio , 建连-客户端失败比例     , %    ,
server_establish_fail_ratio , 建连-服务端失败比例     , %    ,
tcp_transfer_fail           , 传输-失败次数           , 次   , 所有传输错误。
tcp_transfer_fail_ratio     , 传输-失败比例           , %    ,
tcp_rst_fail                , 重置次数                , 连接 , 所有重置错误。
tcp_rst_fail_ratio          , 重置比例                , %    ,
client_source_port_reuse    , 建连-客户端端口复用     , 连接 ,
server_syn_miss             , 建连-服务端 SYN 缺失    , 连接 ,
client_establish_other_rst  , 建连-客户端其他重置     , 连接 ,
client_ack_miss             , 建连-客户端 ACK 缺失    , 连接 ,
server_reset                , 建连-服务端直接重置     , 连接 ,
server_establish_other_rst  , 建连-服务端其他重置     , 连接 ,
client_rst_flow             , 传输-客户端重置         , 连接 ,
server_rst_flow             , 传输-服务端重置         , 连接 ,
server_queue_lack           , 传输-服务端队列溢出     , 连接 ,
tcp_timeout                 , 传输-TCP 连接超时       , 连接 ,
client_half_close_flow      , 断连-客户端半关         , 连接 , TCP 断连异常的场景之一，见文档描述。
server_half_close_flow      , 断连-服务端半关         , 连接 , TCP 断连异常的场景之一，见文档描述。
ooo                         , TCP 乱序                , 包   ,
ooo_tx                      , TCP 客户端乱序           , 包   ,
ooo_rx                      , TCP 服务端乱序           , 包   ,

rtt                         , 平均 TCP 建连时延       , us ,
tls_rtt                     , 平均 TLS 建连时延       , us ,
rtt_client                  , 平均 TCP 建连客户端时延 , us ,
rtt_server                  , 平均 TCP 建连服务端时延 , us ,
srt                         , 平均 TCP/ICMP 系统时延  , us ,
art                         , 平均数据时延            , us ,
cit                         , 平均客户端等待时延      , us ,
rtt_max                     , 最大 TCP 建连时延       , us ,
tls_rtt_max                 , 最大 TLS 建连时延       , us ,
rtt_client_max              , 最大 TCP 建连客户端时延 , us ,
rtt_server_max              , 最大 TCP 建连服务端时延 , us ,
srt_max                     , 最大 TCP/ICMP 系统时延  , us ,
art_max                     , 最大数据时延            , us ,
cit_max                     , 最大客户端等待时延      , us ,
srt_sum                     , 累计 TCP/ICMP 系统时延  , us , 采集周期内全部`TCP/ICMP 系统时延`的加和
srt_count                   , TCP/ICMP 系统时延次数   , 次   , 采集周期内`TCP/ICMP 系统时延`的次数
art_sum                     , 累计数据时延            , us , 采集周期内全部`数据时延`的加和
art_count                   , 数据时延次数            , 次   , 采集周期内`数据时延`的次数
cit_sum                     , 累计客户端等待时延      , us , 采集周期内全部`客户端等待时延`的加和
cit_count                   , 客户端等待时延次数      , 次   , 采集周期内`客户端等待时延`的次数
duration                    , 流持续时间              , us , 表示流的首包到尾包（注意不是 end_time）的时长。

l7_request                  , 应用请求                , 个   ,
l7_response                 , 应用响应                , 个   ,
rrt                         , 平均应用时延            , us ,
rrt_sum                     , 累计应用时延            , us , 采集周期内全部`应用时延`的加和
rrt_count                   , 应用时延次数            , 次   , 采集周期内`应用时延`的次数
rrt_max                     , 最大应用时延            , us ,
l7_error                    , 应用异常                , 个   ,
l7_client_error             , 应用客户端异常          , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 response_status 字段的说明 
l7_server_error             , 应用服务端异常          , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 response_status 字段的说明
l7_server_timeout           , 应用服务端超时          , 个   , 应用超时的统计次数（默认配置下：TCP 类应用在 1800s 内未采集到响应，UDP 类应用在 150s 内未采集到响应）
l7_error_ratio              , 应用异常比例            , %    ,
l7_client_error_ratio       , 应用客户端异常比例      , %    ,
l7_server_error_ratio       , 应用服务端异常比例      , %    ,
l7_parse_failed             , 应用协议解析失败        , 包   , 累计应用协议解析失败次数，最大值 MAX_U32

row                         , 行数                   , 个   ,     
