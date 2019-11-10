trident.proto
-------------

* Group字段含义

     字段      | string类型举例        | 零值特殊含义 | 匹配ANY的值
     ----------|-----------------------|--------------|-------------
     id        |                       | 非法         | 无
     epc_id    |                       | 匹配ANY      | 0
     type      |                       | NAMED        | 无
     vm_ids    |                       | 匹配ANY      | 无
     ips       | 192.168.1.1/24        | 无           | 无
     ip_ranges | 1.1.1.1-1.1.1.3       | 无           | 无

* FlowAcl字段含义

     字段           | string类型举例        | 零值特殊含义 | 匹配ANY的值
     ---------------|-----------------------|--------------|----------------
     id             |                       | 非法         | 无
     tap_type       |                       | 匹配ANY      | nil或0
     protocol       |                       | 匹配0        | 256
     src_ports      | 1000,100-1000         | 匹配0        | nil或0-65535
     dst_ports      | 1000,100-1000         | 匹配0        | nil或0-65535
     vlan           |                       | 匹配ANY      | nil或0
     src_group_ids  |                       | 匹配ANY      | nil或0
     dst_group_ids  |                       | 匹配ANY      | nil或0
