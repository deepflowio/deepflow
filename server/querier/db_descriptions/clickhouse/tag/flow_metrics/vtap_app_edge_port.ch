# Name                     , DisplayName                , Description
time                       , 时间                       ,

region                     , 区域                       ,
az                         , 可用区                     ,
host                       , 宿主机                     , 承载虚拟机的宿主机。
chost                      , 云服务器                   , 包括虚拟机、裸金属服务器。
vpc                        , VPC                        ,
subnet                     , 子网                       ,
router                     , 路由器                     ,
dhcpgw                     , DHCP 网关                  ,
lb                         , 负载均衡器                 ,
lb_listener                , 负载均衡监听器             ,
natgw                      , NAT 网关                   ,
redis                      , Redis                      ,
rds                        , RDS                        ,
pod_cluster                , K8s 容器集群               ,
pod_ns                     , K8s 命名空间               ,
pod_node                   , K8s 容器节点               ,
pod_ingress                , K8s Ingress                ,
pod_service                , K8s 容器服务               ,
pod_group_type             , K8s 工作负载类型           ,
pod_group                  , K8s 工作负载               , 例如 Deployment、StatefulSet、Daemonset 等。
pod                        , K8s 容器 POD               ,
service                    , 服务                       ,
resource_gl0_type          , 类型-容器 POD 优先         ,
resource_gl0               , 资源-容器 POD 优先         ,
resource_gl1_type          , 类型-工作负载优先          ,
resource_gl1               , 资源-工作负载优先          ,
resource_gl2_type          , 类型-服务优先              ,
resource_gl2               , 资源-服务优先              ,
tap_port_host              , 采集网卡所属宿主机           ,
tap_port_chost             , 采集网卡所属云服务器         ,
tap_port_pod_node          , 采集网卡所属容器节点         ,

labels                     , K8s Labels                 ,

ip                         , IP 地址                    ,
is_ipv4                    , IPv4 标志                  ,
is_internet                , Internet IP 标志           , IP 地址是否为外部 Internet 地址。
protocol                   , 网络协议                   ,

tunnel_type                , 隧道类型                   ,

server_port                , 服务端口                   ,

l7_protocol                , 应用协议                   ,

tap                        , 采集点                     , Traffic Access Point，流量采集点，使用固定值（虚拟网络）表示云内流量，其他值表示传统 IDC 流量（支持最多 254 个自定义值表示镜像分光的位置）。
vtap                       , 采集器                     ,
tap_port                   , 采集位置标识               , 当采集位置类型为本地网卡时，此值表示采集网卡的 MAC 地址后缀（后四字节）。
tap_port_name              , 采集位置名称               , 当采集位置类型为本地网卡时，此值表示采集网卡的名称。
tap_port_type              , 采集位置类型               , 表示流量采集位置的类型，包括本地网卡（云内流量）、云网关网卡（云网关流量）、分光镜像（传统 IDC 流量）等。
tap_side                   , 路径统计位置               , 采集位置在流量路径中所处的逻辑位置，例如客户端网卡、客户端容器节点、服务端容器节点、服务端网卡等。
