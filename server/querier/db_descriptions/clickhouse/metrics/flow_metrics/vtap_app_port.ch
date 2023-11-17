# Field                     , DisplayName          , Unit , Description
request                     , 请求                 , 个   , 请求总数
response                    , 响应                 , 个   , 响应总数

rrt                         , 平均时延             , 微秒 , 统计周期内所有应用时延的平均值，一个应用时延由响应时间与请求时间的时差算得
rrt_max                     , 最大时延             , 微秒 , 统计周期内所有应用时延的最大值，一个应用时延由响应时间与请求时间的时差算得

error                       , 异常                 , 个   , 异常包含客户端异常 + 服务端异常，根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
client_error                , 客户端异常           , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明 
server_error                , 服务端异常           , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
timeout                     , 超时                 , 个   , 未采集到响应的请求总数，默认超时时间 TCP 1800s，UDP 150s
error_ratio                 , 异常比例             , %    , 异常请求的百分比，通过`异常 / 响应`计算得，即 `error / response`
client_error_ratio          , 客户端异常比例       , %    , 客户端异常请求的百分比，通过`客户端异常 / 响应`计算得，即 `client_error / response`
server_error_ratio          , 服务端异常比例       , %    , 客户端异常请求的百分比，通过`服务端异常 / 响应`计算得，即 `server_error / response`
row                         , 行数                , 个   ,  
