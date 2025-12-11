# Field                     , DisplayName          , Unit , Description
request                     , 请求                 , 个   , 请求总数
response                    , 响应                 , 个   , 响应总数
direction_score             , 方向得分             ,      , 算法推理应用层连接方向（客户端、服务端角色）的准确性得分值，得分越高连接方向的准确性越高，得分最高 255
response_ratio              , 响应比例             , %    , `响应 / 请求`
success_ratio               , 正常比例             , %    , `1 - 异常 / 响应`

rrt                         , 平均时延             , us , 采集周期内所有应用时延的平均值，单次应用时延等于响应与请求的时间差
rrt_max                     , 最大时延             , us , 采集周期内所有应用时延的最大值，单次应用时延等于响应与请求的时间差

error                       , 异常                 , 个   , `客户端异常 + 服务端异常`
client_error                , 客户端异常           , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
server_error                , 服务端异常           , 个   , 根据具体应用协议的响应码判断异常，不同协议的定义见 `l7_flow_log` 中 `response_status` 字段的说明
timeout                     , 超时                 , 个   , 应用超时的统计次数（默认配置下：TCP 类应用在 1800s 内未采集到响应，UDP 类应用在 150s 内未采集到响应）
error_ratio                 , 异常比例             , %    , `异常 / 响应`
client_error_ratio          , 客户端异常比例       , %    , `客户端异常 / 响应`
server_error_ratio          , 服务端异常比例       , %    , `服务端异常 / 响应`
timeout_ratio               , 超时比例            , %    , `超时 / 请求`
row                         , 行数                , 个   ,  
