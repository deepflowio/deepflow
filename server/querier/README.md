架构
====

engine/
  - DB目录 定义DBEngine结构，实现sql的translate
  - TODO：client目录 获取连接及执行语句
  - engine.go 定义Engine接口，所有db的Engine结构体需实现该接口

parse/
  - parse.go 定义了Parser结构体，用于sql解析

支持数据库：
-------------------------------------------------
- ClickHouse
  - clickhouse.go
    - 实现clickhouse的Engine
  - clickhouse/view
    - 用于转换sql的view结构体


数据库语句及字段说明
====================

基础语句
--------
- 获取所有数据库
  - 请求语句
  ```
  sql=show databases
  ```
  - 返回结构
  ```
  {
      "OPT_STATUS": "SUCCESS",
      "DESCRIPTION": "",
      "result": {
          "columns": [
            "database"
          ],
          "values": [
              [
                "flow_log"
              ],
          ]
      }
  }
  ```

- 获取指定数据库{dbName}中所有数据表
  - 请求语句
  ```
  db={dbName} sql=show tables
  ```
  - 返回结构
  ```
  {
      "OPT_STATUS": "SUCCESS",
      "DESCRIPTION": "",
      "result": {
          "columns": [
            "table"
          ],
          "values": [
              [
                "l4_flow_log"
              ],
              [
                "l7_flow_log"
              ]
          ]
      }
  }
  ```

- 获取指定数据库{dbName}中表{tableName}所支持的tag及描述
  - 请求语句
  ```
  db={dbName} sql=show tags from {tableName}
  ```
  - 返回结构
  ```
  {
      "OPT_STATUS": "SUCCESS",
      "DESCRIPTION": "",
      "result": {
          "columns": [
            "name",
            "client_name",
            "server_name",
            "display_name",
            "type" // tag类型，取值范围：int, int_enum, string, string_enum, resource_name, resource_id, ip
          ],
          "values": [
              [
                "chost",
                "chost_0",
                "chost_1",
                "云服务器",
                "resource_id"
              ],
              [
                "chost_name",
                "chost_name_0",
                "chost_name_1",
                "云服务器名称",
                "resource_name"
              ]
          ]
      }
  }
  ```

- 获取指定数据库{dbName}中表{tableName}所支持的metric及描述
  - 请求语句
  ```
  db={dbName} sql=show metrics from {tableName}
  ```
  - 返回结构
  ```
  {
      "OPT_STATUS": "SUCCESS",
      "DESCRIPTION": "",
      "result": {
          "columns": [
          "name",
          "is_agg",
          "display_name",
          "unit",
          "type", // 指标量类型，取值范围：1.counter 2.gauge 3.delay 4.percentage 5.quotient 6.tag
          "category" // 指标量所属类别
          "operators",
          "permissions",
          "table",
          "description"
          ],
          "values": [
              [
                  "byte",
                  true,
                  "字节",
                  "字节",
                  1,
                  "L3 Throughput",
                  [
                      ">=",
                      "<="
                  ],
                  [
                      true,
                      true,
                      true
                  ],
                  "l4_flow_log",
                  ""
              ],
              [
                  "rtt_max",
                  false,
                  "最大 TCP 建连时延",
                  "微秒",
                  3,
                  "Delay",
                  [
                      ">=",
                      "<="
                  ],
                  [
                      true,
                      true,
                      true
                  ],
                  "l4_flow_log",
                  ""
              ]
          ]
      }
  }
  ```

- 获取指标量所支持的算子及描述
  - 请求语句
  ```
  sql=show metrics functions
  ```
  - 返回结构
  ```
  {
      "OPT_STATUS": "SUCCESS",
      "DESCRIPTION": "",
      "result": {
          "columns": [
              "name",
              "type",           //  算子类型，取值范围： 1.聚合类 2.速率类
              "support_metric_types",         // 表示算子可用于哪几类指标量：取值范围：1.counter 2.gauge 3.delay 4.percentage 5.quotient 6.tag
              "unit_overwrite",
              "additionnal_param_count", // 额外参数支持数量，如 percentile此参数为1，则传递为percentile(byte, 99)
              "is_support_other_operators",
              "value_type"
          ],
          "values": [
              [
                "Sum",
                1,
                [
                    1
                ],
                "$unit",
                0,
                true,
                "Number"
              ],
              [
                "Max",
                1,
                [
                    1,
                    2,
                    3,
                    4,
                    5,
                    9
                ],
                "$unit",
                0,
                true,
                "Number"
              ]
          ]
      }
  }
  ```


Tag字段特殊说明
---------------
- 自动分组-全展开字段
  ```
  auto_instance_type
  auto_instance
  ```
  - 举例
  ```
  select
      auto_instance_type_0,
      auto_instance_0,
      auto_instance_type_1,
      auto_instance_1
  from `flow_log`.`l4_flow_log`
  group by
      auto_instance_type_0,
      auto_instance_0,
      auto_instance_type_1,
      auto_instance_1
  ```
- 自动分组-服务聚合全展开字段：
  ```
  auto_service_type
  auto_service
  ```
  - 举例
  ```
  select
      auto_service_type_0,
      auto_service_0,
      auto_service_type_1,
      auto_service_1
  from `flow_log`.`l4_flow_log`
  group by
      auto_service_type_0,
      auto_service_0,
      auto_service_type_1,
      auto_service_1
  ```


clickhouse指标量及算子特殊处理：
-------------------------------------------------
- Delay/BoundedGauge：忽略 0 的点。认为 0 是无意义的时延值
- Counter/Gauge/Percentage：Min算子，缺时间点时，结果置为0
- Quotient/Percentage：分子不做处理，忽略分母为 0 或 null 的点。认为分子为 0 值时有效、分子为 null 值时无效，且分母为 0 值时无意义

- Counter计数类及Gauge油标类
  - 内层算子使用sum
  - 外层常规算子计算
  - FillNullAsZero为true，Min算子，缺时间点时，结果置为0

  ```
  SELECT AVG(_sum_byte_tx) AS avg_byte_tx
  FROM
  (
      WITH toStartOfInterval(time, toIntervalSecond(60)) AS _time
      SELECT
          SUM(byte_tx) AS _sum_byte_tx,
          _time
      FROM flow_metrics.`vtap_flow_port.1m`
      GROUP BY _time
  )

  ```

- Delay时延类
  - 内层使用算子groupArray将聚合数据作为数组传出（groupArrayIf为0值无意义的处理）
  - 外层针对数组进行聚合，算子:xxxArray
  - IgnoreZero为true，0值无意义

  ```
  SELECT AVGArray(arrayFilter(x -> (x > 0), `_grouparray_rtt_sum/rtt_count`)) AS avg_rtt
  FROM
  (
      WITH toStartOfInterval(time, toIntervalSecond(60)) AS _time
      SELECT
          groupArrayIf(rtt_sum / rtt_count, (rtt_sum / rtt_count) > 0) AS `_grouparray_rtt_sum/rtt_count`,
          _time
      FROM flow_metrics.`vtap_flow_port.1m`
      GROUP BY _time
  )

  ```

- Percentage比例类及Quotient商值类
  - 内层使用sum(x)/sum(y)
  - 外层常规算子计算
  - Percentage比例类FillNullAsZero为true，会将null值作为0值处理

  ```
  SELECT MAX(_div__sum_l7_error__sum_l7_response) * 100 AS max_l7_error_ratio
  FROM
  (
      WITH
          if(SUM(l7_response) > 0, SUM(l7_error) / SUM(l7_response), NULL) AS divide_0diveider_as_null_sum_l7_error_sum_l7_response,
          toStartOfInterval(time, toIntervalSecond(60)) AS _time
      SELECT
          divide_0diveider_as_null_sum_l7_error_sum_l7_response AS _div__sum_l7_error__sum_l7_response,
          _time
      FROM flow_metrics.`vtap_flow_port.1m`
      GROUP BY _time
  )

  ```


- Tag类
  - 仅支持 Uniq、UniqExact、TopK、Any 算子
  - 对应 clickhouse 的 uniq、uniqExact、topK, any
  - 分层翻译时逻辑同 Delay时延类
  - 在不分层的情况下直接使用对应算子

  ```
  SELECT uniqArray(`_grouparray_if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0))`) AS `Uniq(客户端 IP 地址)`
  FROM
  (
      WITH toStartOfInterval(time, toIntervalSecond(60)) AS _time
      SELECT
          groupArray(if(is_ipv4 = 1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0))) AS `_grouparray_if(is_ipv4=1, IPv4NumToString(ip4_0), IPv6NumToString(ip6_0))`,
          _time
      FROM flow_metrics.`vtap_flow_edge_port.1m`
      GROUP BY _time
  )

  ```

- Map类
  - 不支持算子

  ```
  SELECT toJSONString(CAST((metrics_names, metrics_values), 'Map(String, Float64)')) AS `metrics` 
  FROM flow_log.`l7_flow_log`
  ```

- Row类
  - 仅支持Count算子

  ```
  SELECT COUNT(1) AS `row` 
  FROM flow_log.`l7_flow_log`
  ```

注意事项
====================

- 以下Tag字段在使用时需要携带`反引号`
  - `AS`后的中文字符
  - `map_item`类型的tag
  - `k8s.label`, `k8s.annotation`, `cloud.tag`, `os.app`
  - 所有指标量
- 字符串类型的value需要携带`单引号`
- pod_ingress, lb_listener只支持where，不支持select和group
- resource类型tag（不包括tap, vtap）+ip支持node_type和icon_id
- tap_port需和tap_port_type一起select和group
- metrics, tag, attribute, packet_batch不支持AS
- 自动分组相关限制
  - select自动分组的node_type或icon_id时，group需有自动分组名称，不能只有自动分组ID
- HAVING中放带聚合函数的指标量过滤
- WHERE中放不带聚合函数的指标量过滤
- 翻译为除法的指标在聚合函数中会携带 > 0 条件，有以下几种情况
  - delay 类型的指标  
  - 拆层时 percentage, quotient 类型的指标  
  - 不拆层时 flow_metrics 数据库的 percentage 指标
  - flow_log 数据库中 l4_flow_log 和 l7_flow_log 中翻译为除法的指标
