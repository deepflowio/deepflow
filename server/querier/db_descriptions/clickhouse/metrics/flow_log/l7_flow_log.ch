# Field              , DisplayName             , Unit , Description
request              , 请求                    , 个   ,
response             , 响应                    , 个   ,
session_length       , 会话长度                , 字节 , `请求长度 + 响应长度`
request_length       , 请求长度                , 字节 ,
response_length      , 响应长度                , 字节 ,
sql_affected_rows    , SQL 影响行数            , 行   ,
captured_request_byte  , 采集的请求字节数  , 字节 , 对于 Packet 信号源，表示 AF_PACKET 采集到的包长，且不包括四层头；对于 eBPF 信号源，表示一次系统调用的字节数，注意在开启 TCP 流重组时表示多次系统调用的字节数之和。
captured_response_byte , 采集的响应字节数  , 字节 , 对于 Packet 信号源，表示 AF_PACKET 采集到的包长，且不包括四层头；对于 eBPF 信号源，表示一次系统调用的字节数，注意在开启 TCP 流重组时表示多次系统调用的字节数之和。
direction_score      , 方向得分                ,      , 算法推理应用层连接方向（客户端、服务端角色）的准确性得分值，得分越高连接方向的准确性越高，得分最高 255
log_count            , 日志总量                , 个   ,
response_ratio       , 响应比例                , %    , `响应 / 请求`
success_ratio        , 正常比例                , %    , `1 - 异常 / 响应`

error                , 异常                    , 个   , `客户端异常 + 服务端异常`
client_error         , 客户端异常              , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
server_error         , 服务端异常              , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
error_ratio          , 异常比例                , %    , `异常 / 响应`
client_error_ratio   , 客户端异常比例          , %    , `客户端异常 / 响应`
server_error_ratio   , 服务端异常比例          , %    , `服务端异常 / 响应`

response_duration    , 响应时延                , us , 响应与请求的时间差

row                  , 行数                    , 个   ,
