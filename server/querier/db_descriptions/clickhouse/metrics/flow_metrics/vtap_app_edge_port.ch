# Field                     , DisplayName          , Unit , Description
request                     , 请求                 , 个   ,
response                    , 响应                 , 个   ,
direction_score             , 方向得分             ,      , 得分越高时客户端、服务端方向的准确性越高，得分为 255 时方向一定是正确的。

rrt                         , 平均时延             , 微秒 ,
rrt_max                     , 最大时延             , 微秒 ,

error                       , 异常                 , 个   ,
client_error                , 客户端异常           , 个   ,
server_error                , 服务端异常           , 个   ,
timeout                     , 超时                 , 个   ,
error_ratio                 , 异常比例             , %    ,
client_error_ratio          , 客户端异常比例       , %    ,
server_error_ratio          , 服务端异常比例       , %    ,
row                         , 行数                , 个   ,  
