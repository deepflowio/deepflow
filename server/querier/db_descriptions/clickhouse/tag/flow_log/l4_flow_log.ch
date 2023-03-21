# Name                , DisplayName                  , Description
_id                   , UID                          ,
time                  , 时间                         , 将 end_time 取整到秒。

region                , 区域                         ,
az                    , 可用区                       ,
host                  , 宿主机                       , 承载虚拟机的宿主机。
chost                 , 云服务器                     , 包括虚拟机、裸金属服务器。
vpc                   , VPC                          ,
l2_vpc                , 转发 VPC                     , MAC 地址所在的 VPC。
subnet                , 子网                         ,
router                , 路由器                       ,
dhcpgw                , DHCP 网关                    ,
lb                    , 负载均衡器                   ,
lb_listener           , 负载均衡监听器               ,
natgw                 , NAT 网关                     ,
redis                 , Redis                        ,
rds                   , RDS                          ,
pod_cluster           , K8s 容器集群                 ,
pod_ns                , K8s 命名空间                 ,
pod_node              , K8s 容器节点                 ,
pod_ingress           , K8s Ingress                  ,
pod_service           , K8s 容器服务                 ,
pod_group             , K8s 工作负载                 , 例如 Deployment、StatefulSet、Daemonset 等。
pod                   , K8s 容器 POD                 ,
service               , 服务                         ,
resource_gl0_type     , 类型-容器 POD 优先           , 已废弃，请使用 auto_instance_type。
resource_gl0          , 资源-容器 POD 优先           , 已废弃，请使用 auto_instance。
resource_gl1_type     , 类型-工作负载优先            , 已废弃，请使用 auto_service_type。
resource_gl1          , 资源-工作负载优先            , 已废弃，请使用 auto_service。
resource_gl2_type     , 类型-服务优先                , 已废弃，请使用 auto_service_type。
resource_gl2          , 资源-服务优先                , 已废弃，请使用 auto_service。
auto_instance_type    , 类型-容器 POD 优先           , `auto_intance`实例对应的类型。
auto_instance         , 资源-容器 POD 优先           , IP 对应的实例。
auto_service_type     , 类型-服务优先                , `auto_service`实例对应的类型。
auto_service          , 资源-服务优先                , 在`auto_instance`基础上，将容器服务的 ClusterIP 与工作负载聚合为服务。
gprocess              , 进程                         ,

k8s.label             , K8s Label                    ,
cloud.tag             , Cloud Tag                    ,
os.app                , OS APP                       ,

eth_type              , 链路协议                     ,
vlan                  , VLAN TAG                     ,
mac                   , MAC 地址                     ,

ip                    , IP 地址                      ,
is_ipv4               , IPv4 标志                    ,
is_internet           , Internet IP 标志             , IP 地址是否为外部 Internet 地址。
province              , 省份                         , Internet IP 地址所属的省份。
protocol              , 网络协议                     ,

tunnel_tier           , 隧道层数                     ,
tunnel_type           , 隧道类型                     ,
tunnel_tx_id          , 请求隧道 ID                  ,
tunnel_rx_id          , 响应隧道 ID                  ,
tunnel_tx_ip_0        , 请求隧道源 IP                ,
tunnel_tx_ip_1        , 请求隧道目 IP                ,
tunnel_rx_ip_0        , 响应隧道源 IP                ,
tunnel_rx_ip_1        , 响应隧道目 IP                ,
tunnel_tx_mac_0       , 请求隧道源 MAC               ,
tunnel_tx_mac_1       , 请求隧道目 MAC               ,
tunnel_rx_mac_0       , 响应隧道源 MAC               ,
tunnel_rx_mac_1       , 响应隧道目 MAC               ,

client_port           , 客户端口                     ,
server_port           , 服务端口                     ,
tcp_flags_bit         , TCP 标志位集合               , 当前自然分钟内所有包中 TCP 标志位的集合。
syn_seq               , SYN 包 Seq 号                ,
syn_ack_seq           , SYN-ACK 包 Seq 号            ,
last_keepalive_seq    , 心跳包 Seq 号                , 最近一个心跳包中的 SEQ 序列号。
last_keepalive_ack    , 心跳包 Ack 号                , 最近一个心跳包中的 ACK 确认号。

l7_protocol           , 应用协议                     ,

flow_id               , 流日志 ID                    ,
start_time            , 开始时间                     , 单位: 微秒。表示当前自然分钟内流的开始时间，对于新建流表示首包时间。
end_time              , 结束时间                     , 单位: 微秒。表示当前自然分钟内流的结束时间，若流在该分钟内 close，则为尾包时间或流状态机超时的时间。
close_type            , 流结束类型                   ,
status                , 状态                         , 由 close_type（流结束类型）与 protocol（协议）决定：正常结束/周期性上报/非TCP超时=正常，客户端XX=客户端异常，服务端XX/TCP超时=服务端异常，其他结束方式=未知。
is_new_flow           , 新建流                       ,

signal_source         , 信号源                       ,
tap                   , 采集点                       , Traffic Access Point，流量采集点，使用固定值（虚拟网络）表示云内流量，其他值表示传统 IDC 流量（支持最多 254 个自定义值表示镜像分光的位置）。
vtap                  , 采集器                       ,
nat_source            , NAT 源                       ,
tap_port              , 采集位置标识                 , 当采集位置类型为本地网卡时，此值表示采集网卡的 MAC 地址后缀（后四字节）。
tap_port_name         , 采集位置名称                 , 当采集位置类型为本地网卡时，此值表示采集网卡的名称。
tap_port_type         , 采集位置类型                 , 表示流量采集位置的类型，包括本地网卡（云内流量）、云网关网卡（云网关流量）、分光镜像（传统 IDC 流量）等。
tap_side              , 路径统计位置                 , 采集位置在流量路径中所处的逻辑位置，例如客户端网卡、客户端容器节点、服务端容器节点、服务端网卡等。
l2_end                , 二层边界                     , 表示是否是在客户端网卡或服务端网卡处采集的流量。
l3_end                , 三层边界                     , 表示是否是在客户端或服务端所在二层网络内采集的流量。
has_pcap              , PCAP 文件                    , 是否存储了 PCAP 文件
nat_real_ip           , NAT IP 地址                  , NAT 作用前（后）的真实 IP 地址，该值从 TOA（TCP Option Address）中提取，或者根据云平台中 VIP 与 RIP 的映射信息计算。
nat_real_port         , NAT Port                     , NAT 作用前的真实端口号，该值从 TOA（TCP Option Address）中提取。
