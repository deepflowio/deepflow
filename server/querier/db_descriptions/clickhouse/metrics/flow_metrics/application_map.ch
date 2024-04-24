# Field                     , DisplayName          , Unit , Description
request                     , 请求                 , 个   , 请求总数
response                    , 响应                 , 个   , 响应总数
direction_score             , 方向得分             ,      , 算法推理应用协议请求方向时的准确性得分值，得分越高请求方向的准确性越高，得分为 255 表示请求方向的推理结果绝对正确。

rrt                         , 平均时延             , 微秒 , 采集周期内所有应用时延的平均值，单次应用时延等于响应与请求的时间差
rrt_max                     , 最大时延             , 微秒 , 采集周期内所有应用时延的最大值，单次应用时延等于响应与请求的时间差

error                       , 异常                 , 个   , `客户端异常 + 服务端异常`
client_error                , 客户端异常           , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
server_error                , 服务端异常           , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
timeout                     , 超时                 , 个   , 未采集到响应的请求总数，默认超时时间 TCP 1800s，UDP 150s
error_ratio                 , 异常比例             , %    , `异常 / 响应`
client_error_ratio          , 客户端异常比例       , %    , `客户端异常 / 响应`
server_error_ratio          , 服务端异常比例       , %    , `服务端异常 / 响应`
row                         , 行数                , 个   ,  
