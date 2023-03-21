# Name                    , DisplayName              , Description
_id                       , UID                      ,
time                      , 时间                     , 将 end_time 取整到秒。

region                    , 区域                     ,
az                        , 可用区                   ,
host                      , 宿主机                   , 承载虚拟机的宿主机。
chost                     , 云服务器                 , 包括虚拟机、裸金属服务器。
vpc                       , VPC                      ,
l2_vpc                    , 转发 VPC                 , MAC 地址所在的 VPC。
subnet                    , 子网                     ,
router                    , 路由器                   ,
dhcpgw                    , DHCP 网关                ,
lb                        , 负载均衡器               ,
lb_listener               , 负载均衡监听器           ,
natgw                     , NAT 网关                 ,
redis                     , Redis                    ,
rds                       , RDS                      ,
pod_cluster               , K8s 容器集群             ,
pod_ns                    , K8s 命名空间             ,
pod_node                  , K8s 容器节点             ,
pod_ingress               , K8s Ingress              ,
pod_service               , K8s 容器服务             ,
pod_group                 , K8s 工作负载             , 例如 Deployment、StatefulSet、Daemonset 等。
pod                       , K8s 容器 POD             ,
service                   , 服务                     ,
resource_gl0_type         , 类型-容器 POD 优先       , 已废弃，请使用 auto_instance_type。
resource_gl0              , 资源-容器 POD 优先       , 已废弃，请使用 auto_instance。
resource_gl1_type         , 类型-工作负载优先        , 已废弃，请使用 auto_service_type。
resource_gl1              , 资源-工作负载优先        , 已废弃，请使用 auto_service。
resource_gl2_type         , 类型-服务优先            , 已废弃，请使用 auto_service_type。
resource_gl2              , 资源-服务优先            , 已废弃，请使用 auto_service。
auto_instance_type        , 类型-容器 POD 优先       , `auto_intance`实例对应的类型。
auto_instance             , 资源-容器 POD 优先       , IP 对应的实例。
auto_service_type         , 类型-服务优先            , `auto_service`实例对应的类型。
auto_service              , 资源-服务优先            , 在`auto_instance`基础上，将容器服务的 ClusterIP 与工作负载聚合为服务。
gprocess                  , 进程                     , 

k8s.label                 , K8s Label                , K8s 自定义 Label。
attribute                 , Attribute                , OpenTelemetry Span 属性，以及应用协议特有属性。
cloud.tag                 , Cloud Tag                ,
os.app                    , OS APP                   ,

ip                        , IP 地址                  ,
is_ipv4                   , IPv4 标志                ,
is_internet               , Internet IP 标志         , Internet IP 无法关联到实例或子网 CIDR 的 IP。
protocol                  , 网络协议                 ,

tunnel_type               , 隧道类型                 ,

client_port               , 客户端口                 ,
server_port               , 服务端口                 ,
req_tcp_seq               , 请求 TCP Seq 号          ,
resp_tcp_seq              , 响应 TCP Seq 号          ,

l7_protocol               , 应用协议                 , 
l7_protocol_str           , 应用协议                 , 字符串形式。
version                   , 协议版本                 ,
type                      , 日志类型                 ,
request_type              , 请求类型                 ,
request_domain            , 请求域名                 ,
request_resource          , 请求资源                 ,
request_id                , 请求 ID                  ,
response_status           , 响应状态                 ,
response_code             , 响应码                   ,
response_exception        , 响应异常                 ,
response_result           , 响应结果                 ,

app_service               , 应用服务                 ,
app_instance              , 应用实例                 ,
endpoint                  , 端点                     ,
process_id                , 进程 ID                  ,
process_kname             , 内核线程名               ,

trace_id                  , TraceID                  ,
span_id                   , SpanID                   ,
parent_span_id            , ParentSpanID             ,
span_kind                 , Span 类型                , 取自 OpenTelemetry。
x_request_id              , X-Request-ID             ,
http_proxy_client         , HTTP 代理客户端          , 代理转换之前的真实客户端 IP。
syscall_trace_id_request  , 请求 Syscall TraceID     ,
syscall_trace_id_response , 响应 Syscall TraceID     ,
syscall_thread_0          , 请求 Syscall 线程        ,
syscall_thread_1          , 响应 Syscall 线程        ,
syscall_cap_seq_0         , 请求 Syscall 序号        ,
syscall_cap_seq_1         , 响应 Syscall 序号        ,

flow_id                   , 流日志 ID                ,
start_time                , 开始时间                 , 单位: 微秒。表示当前请求开始的时间。
end_time                  , 结束时间                 , 单位: 微秒。表示当前响应开始的时间，但对 OTel 是响应结束时间。

signal_source             , 信号源                   ,
tap                       , 采集点                   , Traffic Access Point，流量采集点，使用固定值（虚拟网络）表示云内流量，其他值表示传统 IDC 流量（支持最多 254 个自定义值表示镜像分光的位置）。
vtap                      , 采集器                   ,
nat_source                , NAT 源                   ,
tap_port                  , 采集位置标识             , 当采集位置类型为本地网卡时，此值表示采集网卡的 MAC 地址后缀（后四字节）。
tap_port_name             , 采集位置名称             , 当采集位置类型为本地网卡时，此值表示采集网卡的名称。
tap_port_type             , 采集位置类型             , 表示流量采集位置的类型，包括 OTel（应用 Span）、eBPF（Socket Data）、本地网卡（云内流量）、云网关网卡（云网关流量）、分光镜像（传统 IDC 流量）等。
tap_side                  , 路径统计位置             , 采集位置在流量路径中所处的逻辑位置，例如客户端应用、客户端进程、客户端网卡、客户端容器节点、服务端容器节点、服务端网卡、服务端进程、服务端应用等。
