# Value , DisplayName     , Description
0       , 正常            , 响应码正常（包括 span.status.code = STATUS_CODE_OK 的 OTel 数据）。
2       , 超时            , 在一定时间内未采集到响应时，请求会标记为超时。采集器`应用会话合并超时设置`配置：DNS 和 TLS 默认 15s，其他协议默认 120s。
3       , 服务端异常      , 响应码表示的含义为服务端侧的异常，例如 HTTP 5XX（包括 span.status.code = STATUS_CODE_ERROR 的 OTel 数据）。
4       , 客户端异常      , 响应码表示的含义为客户端侧的异常，例如 HTTP 4XX。
5       , 未知            , 并发请求量超出采集器缓存能力时，最老的请求会标记为未知（包括 span.status.code = STATUS_CODE_UNSET 的 OTel 数据）。采集器`会话聚合最大条目数`配置：默认缓存 64K 条请求。
6       , 解析失败        , 采集到了响应，但由于内容被截断或被压缩等原因，未能解析到响应码。采集器`Payload 截取`配置：默认解析 Payload 前 1024 字节。
