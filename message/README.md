trident.proto
-------------

* Group字段含义

     字段      | string类型举例        | 值域            | 匹配ANY的值
     ----------|-----------------------|-----------------|-------------
     id        |                       | -1, -2, 1~64000 | 无
     epc_id    |                       | -2~64000        | nil或0
     type      |                       |                 | 无
     ips       | 192.168.1.1/24        |                 | 无
     ip_ranges | 1.1.1.1-1.1.1.3       |                 | 无

* FlowAcl字段含义

     字段           | string类型举例        | 值域         | 匹配ANY的值
     ---------------|-----------------------|--------------|----------------
     id             |                       | 1~64000      | 无
     tap_type       |                       | 0~30         | nil或0
     protocol       |                       | 0~256        | nil或256
     src_ports      | 1000,100-1000         |              | nil或0-65535
     dst_ports      | 1000,100-1000         |              | nil或0-65535
     vlan           |                       | 0,2~4095     | nil或0
     src_group_ids  |                       | 0~64000      | nil或0
     dst_group_ids  |                       | 0~64000      | nil或0

* Interface字段对应程序，为否可以不发送

     字段             | trident | droplet、roze和stream
     -----------------|---------|------------------------
     id               | 是      | 是
     epc_id           | 是      | 是
     ip_resources     | 是      | 是
     region_id        | 是      | 是
     mac              | 是      | 是
     is_vip_interface | 是      | 是
     pod_node_id      | 是      | 是
     pod_cluster_id   | 是      | 是
     if_type          | 是      | 是
     其他             | 否      | 是

* SyncResponse字段对应程序，为否表示不发送

     字段                  | trident | droplet、roze和stream
     ----------------------|---------|------------------------
     status                | 是      | 是
     config                | 是      | 是
     local_config_file     | 是      | 否
     revision              | 是      | 否
     self_update_url       | 是      | 否
     version_platform_data | 是      | 是
     version_acls          | 是      | 是
     version_groups        | 是      | 是
     platform_data         | 是      | 是
     flow_acls             | 是      | 是
     groups                | 是      | 是
     local_segments        | 是      | 否
     remote_segments       | 是      | 否
     tap_types             | 是      | 否
     pod_ips               | 否      | 是
     vtap_ips              | 否      | 是
