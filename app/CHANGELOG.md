 # Change Log

  记录tsdb存储数据的变化和影响


  ## [5.5.9] - 2020-02-13

   - tag变化

      |tag名       | 变化 |  影响的db          | 影响的measurement| 其他影响 |
      | ---        | ---  | ---                | ---              | ---      |
      | host       | 删除 | vtap_usage开头的db | all              |  影响5.5.7及以前的版本升级，app查询使用host_id |
      |ip_bin[_0/1]| 删除 | all                | all              |  app修改查询条件                               |

  ## [5.5.8] - 2020-02-12

  - meauserment命名变化
    - 之前的版本measurement以tag所组成的64位16进制字符串命名。
    - 修改为measuremet名称固定命名，例如: main, mini, main_isp 等
    - 影响: 升级到该版本，measurement数据需要重新导入(秒级，分钟级，10分钟级数据)

  - tag变化

    |tag名       | 变化 |  影响的db          | 影响的measurement| 其他影响 |
    | ---        | ---  | ---                | ---              | ---      |
    | host_id    | 增加 | vtap_usage开头的db | all              |  暂无                  |
    |pod_node_id | 增加 | vtap_usage开头的db | all              |  老版本无，则默认为0   |
    | vtap_id    | 增加 | vtap_usage开头的db | all              |  暂无                  |
    | tap_type   | 增加 | vtap_usage开头的db | all              |  老版本无，则默认为3   |
    | vtap       | 删除 | vtap_usage         | main_cast_type   |  暂无                  |
    | scope      | 删除 | vtap_usage         | main             |  暂无                  |

  ## [5.5.7] - 2019-11-22

  - tag变化

    |tag名       | 变化 |  影响的db          | 影响的measurement     | 其他影响 |
    | ---        | ---  | ---                | ---                   | ---      |
    | tcp_flags  | 增加 | vtap_usage         | 增加x00000300000001d1 |  暂无    |

 - 新增measurement如下:
```
   df_usage_acl           x0000040300000000    _id,acl_direction,acl_gid,direction
   df_fps_acl             x0000040300000000    _id,acl_direction,acl_gid,direction
   df_perf_acl            x0000040300000000    _id,acl_direction,acl_gid,direction
   vtap_usage             x00000300000001d1    _id,_tid,host,ip,ip_bin,ip_version,l3_device_id,l3_device_type,l3_epc_id,region,subnet_id,tcp_flags
```

  ## [5.5.6] - 2019-10-22

 - 新增measurement如下:
```
   df_fps_acl_port        x0000049b00000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type,protocol,server_port
   df_fps_acl_edge_port   x0000049b00010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type,protocol,server_port
   df_geo_acl_port        x2000049b00000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,isp,tap_type,protocol,server_port
   df_geo_acl_port        x4000049b00000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,region,tap_type,protocol,server_port
   df_geo_acl_edge_port   x2000049b00010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,isp,tap_type,protocol,server_port
   df_geo_acl_edge_port   x4000049b00010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,region,tap_type,protocol,server_port
   df_perf_acl_port       x0000049b00000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type,protocol,server_port
   df_type_acl_port       x0000049b00000001    _id,acl_direction,acl_gid,direction,ip,ip_bin,ip_version,tap_type,protocol,server_port
   df_type_acl_edge_port  x0000049b00010000    _id,acl_direction,acl_gid,direction,ip_0,ip_1,ip_bin_0,ip_bin_1,ip_version,tap_type,protocol,server_port
```

  ## [5.5.5] - 2019-08-22

  - 增加存储秒级数据
    - 以下数据库会同时存储秒级数据, 写入数据库的retention policy为s1, 默认保留1天:
      - df_usage[xxx]
      - df_fps[xxx]
