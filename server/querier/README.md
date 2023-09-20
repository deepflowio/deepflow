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
          "display_name",
          "unit",
          "type", // 指标量类型，取值范围：1.counter 2.gauge 3.delay 4.percentage 5.quotient 6.tag
          "category" // 指标量所属类别
          ],
          "values": [
              [
                  "byte",
                  "字节",
                  "字节"，
                  1,
                  "l3-traffic-flow-log"
              ],
              [
                  "rtt_max",
                  "最大TCP建连时延",
                  "微秒",
                  3,
                  "l4-latency-flow-log"
              ]
          ]
      }
  }
  ```

- 获取指标量所支持的算子及描述
  - 请求语句
  ```
  sql=show metric function
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
              "additionnal_param_count" // 额外参数支持数量，如 percentile此参数为1，则传递为percentile(byte, 99)
          ],
          "values": [
              [
                  "Sum",
                  1,
                  [0],
                  "$unit",
                  0
              ],
              [
                  "Max",
                  1,
                  [0, 1, 2, 3],
                  "$unit",
                  0
              ]
          ]
      }
  }
  ```


Tag字段特殊说明
---------------
- 自动分组-全展开字段
  ```
  resource_type_gl0
  resource_gl0 或 resource_name_gl0
  ```
  - 举例
  ```
  select
      resource_type_gl0_0,
      resource_name_gl0_0,
      resource_type_gl0_1,
      resource_name_gl0_1
  from `flow_log`.`l4_flow_log`
  group by
      resource_type_gl0_0,
      resource_name_gl0_0,
      resource_type_gl0_1,
      resource_name_gl0_1
  ```
  - `注意`：对`resource_type_gl0/resource_name_gl0`进行select或者group by时，始终会额外返回`subnet/subnet_name`和`ip`字段
- 自动分组-工作负载聚合全展开字段：
  ```
  resource_type_gl1
  resource_gl1 或 resource_name_gl1
  ```
  - 举例
  ```
  select
      resource_type_gl1_0,
      resource_name_gl1_0,
      resource_type_gl1_1,
      resource_name_gl1_1
  from `flow_log`.`l4_flow_log`
  group by
      resource_type_gl1_0,
      resource_name_gl1_0,
      resource_type_gl1_1,
      resource_name_gl1_1
  ```
  - `注意`：对`resource_type_gl1/resource_name_gl1`进行select或者group by时，始终会额外返回`subnet/subnet_name`和`ip`字段
- 自动分组-服务聚合全展开字段：
  ```
  resource_type_gl2
  resource_gl2 或 resource_name_gl2
  ```
  - 举例
  ```
  select
      resource_type_gl2_0,
      resource_name_gl2_0,
      resource_type_gl2_1,
      resource_name_gl2_1
  from `flow_log`.`l4_flow_log`
  group by
      resource_type_gl2_0,
      resource_name_gl2_0,
      resource_type_gl2_1,
      resource_name_gl2_1
  ```
  - `注意`：对`resource_type_gl2/resource_name_gl2`进行select或者group by时，始终会额外返回`subnet/subnet_name`和`ip`字段


clickhouse指标量及算子特殊处理：
-------------------------------------------------
- Counter计数类及Gauge油标类
  - 内层算子使用sum
  - 外层常规算子计算
  - Counter计数类FillNullAsZero为true，会将null值作为0值处理

  ```

  SELECT AVG(_sum_byte_tx) AS avg_byte_tx
  FROM
  (
      SELECT SUM(byte_tx) AS _sum_byte_tx
      FROM l4_flow_log
  )

  ```

- Delay时延类
  - 内层使用算子groupArray将聚合数据作为数组传出（groupArrayIf为0值无意义的处理）
  - 外层针对数组进行聚合，算子:xxxArray
  - IgnoreZero为true，0值无意义

  ```
  SELECT AVGArray(arrayFilter(x -> x>0, _rtt_sum)) AS avg_rtt
  FROM
  (
      WITH if(rtt_count > 0, rtt_sum / rtt_count, 0)
      SELECT
          groupArrayIf(rtt_sum, rtt_sum != 0) AS _rtt_sum,
      FROM vtap_flow_port.`1m`
  )

  ```

- Percentage比例类及Quotient商值类
  - 内层使用sum(x)/sum(y)
  - 外层常规算子计算
  - Percentage比例类FillNullAsZero为true，会将null值作为0值处理

  ```

  SELECT MAX(_div__sum_l7_request__sum_l7_response) AS max_l7_error_ratio
  FROM
  (
      SELECT SUM(l7_request) / SUM(l7_response) AS _div__sum_l7_request__sum_l7_response
      FROM l4_flow_log
  )

  ```


- Tag类
  - 仅支持Uniq及UniqExact算子
  - 内层使用uniqIf()
  - 外层使用Sum
  - 在不分层的情况下直接使用uniqIf

  ```
  SELECT SUM(_uniq_ip_0) AS uniq_ip_0
  FROM
  (
    SELECT uniqIf([toString(ip4_0), toString(subnet_id_0), toString(is_ipv4), toString(ip6_0)], NOT (((is_ipv4 = 1) OR (ip6_0 = toIPv6('::'))) AND ((is_ipv4 = 0) OR (ip4_0 = toIPv4('0.0.0.0'))))) AS _uniq_ip_0
    FROM l4_flow_log
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
