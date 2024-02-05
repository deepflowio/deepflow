# Name                     , DisplayName                , Description
_id                        , UID                        ,
time                       , 时间                       ,

region                     , 区域                       ,
az                         , 可用区                     ,
host                       , 宿主机                     , 承载虚拟机的宿主机。
chost                      , 云服务器                   , 包括虚拟机、裸金属服务器。
vpc                        , VPC                        ,
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
gprocess                   , 进程                       ,
host_ip                    , 宿主机                     , 宿主机的管理 IP。
host_hostname              , 宿主机                     , 宿主机的 Hostname。
chost_ip                   , 云服务器                   , 云服务器的主 IP。
chost_hostname             , 云服务器                   , 云服务器的 Hostname。
pod_node_ip                , K8s 容器节点               , 容器节点的主 IP。
pod_node_hostname          , K8s 容器节点               , 容器节点的 Hostname。

k8s.label                  , K8s Label                  ,
k8s.annotation             , K8s Annotation             ,
k8s.env                    , K8s Env                    ,
cloud.tag                  , Cloud Tag                  ,

ip                         , IP 地址                    ,
is_ipv4                    , IPv4 标志                  ,

app_service                , 应用服务                    ,
app_instance               , 应用实例                    ,

trace_id                   , TraceID                    ,
span_name                  , Span名称                    ,

vtap                       , 采集器                      ,

profile_value_unit         , 单位                        ,
profile_event_type         , 剖析类型                    ,
profile_create_timestamp   , 聚合时间                    ,
profile_in_timestamp       , 写入时间                    ,
profile_language_type      , 语言类型                    ,
profile_id                 , ProfileID                   ,
