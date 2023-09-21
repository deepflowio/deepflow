# Name                     , DisplayName                , Description
time_str                   , 时间                       ,
time                       , 时间                       , 将 end_time 取整到秒。
start_time                 , 开始时间                   , 单位: 微秒。表示事件开始的时间。
end_time                   , 结束时间                   , 单位: 微秒。表示事件结束的时间，

region                     , 区域                       ,
az                         , 可用区                     ,
host                       , 宿主机                     , 承载虚拟机的宿主机。
chost                      , 云服务器                   , 包括虚拟机、裸金属服务器。
vpc                        , VPC                        ,
router                     , 路由器                     ,
subnet                     , 子网                       ,
dhcpgw                     , DHCP 网关                  ,
lb                         , 负载均衡器                 ,
natgw                      , NAT 网关                   ,
redis                      , Redis                      ,
rds                        , RDS                        ,
pod_cluster                , K8s 容器集群               ,
pod_ns                     , K8s 命名空间               ,
pod_node                   , K8s 容器节点               ,
pod_service                , K8s 容器服务               ,
pod_group_type             , K8s 工作负载类型           ,
pod_group                  , K8s 工作负载               ,
pod                        , K8s 容器 POD               ,
service                    , 服务                       ,
auto_instance_type         , 类型-容器 POD 优先         , `auto_instance`实例对应的类型。
auto_instance              , 资源-容器 POD 优先         , IP 对应的实例。
auto_service_type          , 类型-服务优先              , `auto_service`实例对应的类型。
auto_service               , 资源-服务优先              , 在`auto_instance`基础上，将容器服务的 ClusterIP 与工作负载聚合为服务。
gprocess                   , 进程                       ,

attribute                  , Attribute                  , 事件特有属性
k8s.label                  , K8s Label                  ,
cloud.tag                  , Cloud Tag                  ,
os.app                     , OS APP                     ,

ip                         , IP 地址                    ,
is_ipv4                    , IPv4 标志                  ,

event_type                 , 事件类型                   ,
event_desc                 , 事件信息                   ,

app_instance               , 应用实例                   ,
vtap                       , 采集器                     ,
signal_source              , 信号源                     ,
