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

clickhouse固定句式获取metrics/tags等可用取值
-------------------------------------------------
- db={dbName} sql=show tags from {tableName}
  - 获取指定数据库dbName中tableName表所支持的Tag描述
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
            "type"
          ],
          "values": [
              [
                "vm",
                "vm_0",
                "vm_1",
                "云服务器",
                "resource_id"
              ],
              [
                "vm_name",
                "vm_name_0",
                "vm_name_1",
                "云服务器名称",
                "resource_name"
              ]
          ]
      }
  }
  ```

- db={dbName} sql=show metrics from {tableName}
  - 获取指定数据库dbName中tableName表所支持的指标量
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
          "type", // 1.counter 2.gauge 3.delay 4.percentage
          "category"
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

- sql=show metric functions
  - 获取所有指标量算子
  - 返回结构
  ```
  {
      "OPT_STATUS": "SUCCESS",
      "DESCRIPTION": "",
      "result": {
          "columns": [
              "name",
              "type",           // 1.聚合类 2.速率类
              "support_metric_types",         // 支持的metric类型 1.counter 2.gauge 3.delay 4.percentage (数学类默认支持全部)
              "unit_overwrite",
              "additionnal_param_count"       // 额外参数支持数量，如 percentile此参数为1，则传递为percentile(byte, 99)
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

clickhouse指标量及算子特殊处理：
-------------------------------------------------
- 时延类(用于解决原先avg单双层结果不一致的问题)
  - 内层使用算子groupArray将聚合数据作为数组传出（groupArrayIf为0值无意义的处理）
  - 外层针对数组进行聚合，算子:xxxArray

  ```

  SELECT AVGArray(arrayFilter(x -> x!=0, _rtt_sum)) AS avg_rtt
  FROM
  (
      WITH if(rtt_count > 0, rtt_sum / rtt_count, 0)
      SELECT
          groupArrayIf(rtt_sum, rtt_sum != 0) AS _rtt_sum,
          host_id,
          time
      FROM vtap_flow_port.`1m`
      WHERE ((time >= toDateTime(1647235440)) AND (time <= toDateTime (1647238920))) AND (NOT (host_id = 0))
      GROUP BY
          host_id,
          time
  )
  GROUP BY host_id
  
  ```
