# Field              , DisplayName             , Unit , Description
request              , 请求                    , 个   ,
response             , 响应                    , 个   ,
session_length       , 会话长度                , 字节 , 请求长度 + 响应长度。
request_length       , 请求长度                , 字节 ,
response_length      , 响应长度                , 字节 ,
sql_affected_rows    , SQL 影响行数            , 行   ,
captured_request_byte  , 采集的请求字节数  , 字节 , 对于 Packet 信号源，表示 AF_PACKET 采集到的包长，且不包括四层头；对于 eBPF 信号源，表示一次系统调用的字节数，注意在开启 TCP 流重组时表示多次系统调用的字节数之和。
captured_response_byte , 采集的响应字节数  , 字节 , 对于 Packet 信号源，表示 AF_PACKET 采集到的包长，且不包括四层头；对于 eBPF 信号源，表示一次系统调用的字节数，注意在开启 TCP 流重组时表示多次系统调用的字节数之和。
direction_score      , 方向得分                ,      , 得分越高时客户端、服务端方向的准确性越高，得分为 255 时方向一定是正确的。
log_count            , 日志总量                , 个   ,

error                , 异常                    , 个   , 客户端异常 + 服务端异常。
client_error         , 客户端异常              , 个   ,
server_error         , 服务端异常              , 个   ,
error_ratio          , 异常比例                , %    , 异常 / 响应。
client_error_ratio   , 客户端异常比例          , %    , 客户端异常 / 响应。
server_error_ratio   , 服务端异常比例          , %    , 服务端异常 / 响应。

response_duration    , 响应时延                , 微秒 , 日志类型为会话时，响应时延 = 结束时间 - 开始时间。

row                  , 行数                    , 个   ,     
