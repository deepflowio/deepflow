# Field              , DisplayName             , Unit , Description
request              , 请求                    , 个   ,
response             , 响应                    , 个   ,
session_length       , 会话长度                , 字节 , 请求长度 + 响应长度。
request_length       , 请求长度                , 字节 ,
response_length      , 响应长度                , 字节 ,
sql_affected_rows    , SQL 影响行数            , 行   ,
log_count            , 日志总量                , 个   ,

error                , 异常                    , 个   , 客户端异常 + 服务端异常。
client_error         , 客户端异常              , 个   ,
server_error         , 服务端异常              , 个   ,
error_ratio          , 异常比例                , %    , 异常 / 响应。
client_error_ratio   , 客户端异常比例          , %    , 客户端异常 / 响应。
server_error_ratio   , 服务端异常比例          , %    , 服务端异常 / 响应。

response_duration    , 响应时延                , 微秒 , 日志类型为会话时，响应时延 = 结束时间 - 开始时间。

ip_version           , IP 类型                 , 个   ,
server_port          , 服务端口                , 个   ,
version              , 协议版本                , 个   ,
request_type         , 请求类型                , 个   ,
request_domain       , 请求域名                , 个   ,
request_resource     , 请求资源                , 个   ,
response_code        , 响应码                  , 个   ,
response_result      , 响应结果                , 个   ,
tap                  , 采集点                  , 个   ,
vtap                 , 采集器                  , 个   ,