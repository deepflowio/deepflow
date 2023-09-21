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

labels                     , K8s Labels                 ,

ip                         , IP 地址                    ,
is_ipv4                    , IPv4 标志                  ,
protocol                   , 网络协议                   ,

server_port                , 服务端口                   ,

l7_protocol                , 应用协议                   ,

tap                        , 采集点                     ,
vtap                       , 采集器                     ,
