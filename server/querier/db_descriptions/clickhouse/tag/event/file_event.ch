# Name                     , DisplayName                , Description
time_str                   , 时间                       ,
_id                        , UID                        ,
time                       , 时间                       , 将 end_time 取整到秒。
start_time                 , 开始时间                   , 单位: 微秒。表示事件开始的时间。
end_time                   , 结束时间                   , 单位: 微秒。表示事件结束的时间，

region                     , 区域                       ,
az                         , 可用区                     ,
host                       , 宿主机                     , 承载虚拟机的宿主机。
chost                      , 云主机                     , 包括虚拟机、裸金属服务器。
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
service                    , 服务                       , 已废弃，请使用 pod_service
auto_instance_type         , 自动实例类型                , `auto_instance`实例对应的类型。
auto_instance              , 自动实例                   , IP 对应的实例，实例为IP时，auto_instance_id显示为子网ID。
auto_service_type          , 自动服务类型                , `auto_service`实例对应的类型。
auto_service               , 自动服务                   , 在`auto_instance`基础上，将容器服务的 ClusterIP 与工作负载聚合为服务，实例为IP时，auto_service_id显示为子网ID。
gprocess                   , 进程                       ,
host_ip                    , 宿主机                     , 宿主机的管理 IP。
host_hostname              , 宿主机                     , 宿主机的 Hostname。
chost_ip                   , 云主机                     , 云主机的主 IP。
chost_hostname             , 云主机                     , 云主机的 Hostname。
pod_node_ip                , K8s 容器节点               , 容器节点的主 IP。
pod_node_hostname          , K8s 容器节点               , 容器节点的 Hostname。

attribute                  , Attribute                  , 事件特有属性
k8s.label                  , K8s Label                  ,
k8s.annotation             , K8s Annotation             ,
k8s.env                    , K8s Env                    ,
cloud.tag                  , Cloud Tag                  ,
os.app                     , OS APP                     ,
biz_service.group          , 服务组                     ,

ip                         , IP 地址                    ,
is_ipv4                    , IPv4 标志                  ,

event_type                 , 事件类型                   ,

process_kname              , 系统进程                   ,
app_instance               , 应用实例                   ,
vtap                       , 采集器                     , 已废弃，请使用 agent。
agent                      , 采集器                     ,
signal_source              , 信号源                     ,

mount_source               , 挂载源                     , 目录挂载源，例如：`/dev/sda1` 表示块设备，`proc` 等（其他如 `sysfs`，`tmpfs`）表示虚拟文件系统，`10.1.2.3:/path` 表示 NFS 文件系统，`/var/lib/docker/...` 或 `overlay` 表示容器内目录的挂载源。
mount_point                , 挂载点                     , 目录挂载点，当进程访问其他命名空间（`nsid`）下的文件时，显示为 `$nsid:/$mount_point`。
file_dir                   , 文件夹                     , 目录，当进程访问其他命名空间（`nsid`）下的文件时，显示为 `$nsid:/$file_dir`。
file_name                  , 文件名                     ,
file_type                  , 文件类型                   ,
offset                     , 偏移量                     ,
syscall_thread             , Syscall 线程               ,
syscall_coroutine          , Syscall 协程               ,
