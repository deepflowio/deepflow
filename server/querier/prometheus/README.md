Prometheus Promql 文档
====

查询流程：
---------
  - api输入 -> 1.instant查询： promql.go(PromQueryExecute)  2.range查询：    promql.go(PromQueryRangeExecute)
  - -> promql.go(NewInstantQuery)将promql传入，由prometheus代码解析并在queryable.go(Select)中获得语法树
    - promql语法树为queryable.go(Select)中的`hints *storage.SelectHints, matchers ...*labels.Matcher`参数
  - -> queryable.go(remote.ToQuery)生成remote_read请求结构, queryable.go(Select)执行remote_read.go(PromReaderExecute)进行查询
  - -> remote_read.go(PromReaderTransToSQL) 将remote_read请求结构翻译成querier_sql
    - 请求结构参考Prometheus RemoteRead API 文档
  - -> clickhouse.go(ExecuteQuery)执行查询
  - -> remote_read.go(RespTransToProm) 将querier返回结果转换为remote_read返回结构
    - 返回结构参考Prometheus RemoteRead API 文档
  - -> 剩余返回结果的聚合和过滤等操作由prometheus代码完成

metrics解析逻辑(metricsName为querier的GetMetrics函数所返回的指标量名称):
  - db：`flow_log`, `event`, `deepflow_system` 
    - metrics: `{db}__{table}__{metricsName}`
  - db: `flow_metrics`
    - metrics: `{db}__{table}__{metricsName}__{datasource}`
  - db: `ext_metrics`, prometheus写入的指标量, 因为需要支持prometheus页面的remote_read, 所以直接使用指标量名称裸查, 并且去掉由ext_common中getExtMetrics所增加的`metrics.`前缀
    - metrics: `strings.TrimPrefix(metricsName, 'metrics.')`
    - querier针对ext_metrics查询的逻辑与其他db不同，查询时需要将table设置为`prometheus.{metricsName}`, 查询的metricsName需携带`metrics.`前缀
  - db: `ext_metrics`, influxdb写入的指标量 TODO
    - metrics: `ext_metrics__ext_common__influxdb.{metricsName}`

Prometheus RemoteRead API 文档
====

请求：
---------
  - url: /api/v1/prom/read
  - 请求格式：
    1. m1
    ```
    prompb.ReadRequest{
      Queries: []*prompb.Query{
        &prompb.Query{
          StartTimestampMs: 1665912411000,
          EndTimestampMs:   1665912711000,
          Matchers:         []*prompb.LabelMatcher{
            &prompb.LabelMatcher{
              Type:                 0,
              Name:                 "__name__",
              Value:                "m1",
            },
          },
          Hints: &prompb.ReadHints{
            StepMs:               0,
            Func:                 "",
            StartMs:              1665912411000,
            EndMs:                1665912711000,
            Grouping:             []string{},
            By:                   false,
            RangeMs:              0,
          },
        },
      },
      AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{},
    }
    ```

    2. m1{node="node25"}
    ```
    prompb.ReadRequest{
      Queries: []*prompb.Query{
        &prompb.Query{
          StartTimestampMs: 1665912411000,
          EndTimestampMs:   1665912711000,
          Matchers:         []*prompb.LabelMatcher{
            &prompb.LabelMatcher{
              Type:                 0,
              Name:                 "node",
              Value:                "node25",
            },
            &prompb.LabelMatcher{
              Type:                 0,
              Name:                 "__name__",
              Value:                "m1",
            },
          },
          Hints: &prompb.ReadHints{
            StepMs:               0,
            Func:                 "",
            StartMs:              1665912411000,
            EndMs:                1665912711000,
            Grouping:             []string{},
            By:                   false,
            RangeMs:              0,
          },
        },
      },
      AcceptedResponseTypes: []prompb.ReadRequest_ResponseType{},
    }
    ```

返回：
---------
  - 返回结构：
    ```
    &prompb.ReadResponse{
      Results: []*prompb.QueryResult{
        &prompb.QueryResult{
          Timeseries: []*prompb.TimeSeries{
            &prompb.TimeSeries{
              Labels: []prompb.Label{
                prompb.Label{
                  Name:                 "__name__",
                  Value:                "node_memory_Active_bytes",
                },
                prompb.Label{
                  Name:                 "chart",
                  Value:                "prometheus-15.11.0",
                },
                prompb.Label{
                  Name:                 "instance",
                  Value:                "10.1.20.25:9100",
                },
                prompb.Label{
                  Name:                 "job",
                  Value:                "kubernetes-service-endpoints",
                },
                prompb.Label{
                  Name:                 "namespace",
                  Value:                "prometheus",
                },
                prompb.Label{
                  Name:                 "release",
                  Value:                "prometheus",
                },
                prompb.Label{
                  Name:                 "service",
                  Value:                "prometheus-node-exporter",
                },
                prompb.Label{
                  Name:                 "app",
                  Value:                "prometheus",
                },
                prompb.Label{
                  Name:                 "app_kubernetes_io_managed_by",
                  Value:                "Helm",
                },
                prompb.Label{
                  Name:                 "node",
                  Value:                "node25",
                },
                prompb.Label{
                  Name:                 "component",
                  Value:                "node-exporter",
                },
                prompb.Label{
                  Name:                 "heritage",
                  Value:                "Helm",
                },
              },
              Samples: []prompb.Sample{
                prompb.Sample{
                  Value:                10097123328.000000,
                  Timestamp:            1665912671000,
                },
                prompb.Sample{
                  Value:                10068422656.000000,
                  Timestamp:            1665912431000,
                },
                prompb.Sample{
                  Value:                10077310976.000000,
                  Timestamp:            1665912491000,
                },
                prompb.Sample{
                  Value:                10084495360.000000,
                  Timestamp:            1665912551000,
                },
                prompb.Sample{
                  Value:                10097037312.000000,
                  Timestamp:            1665912611000,
                },
              },
              Exemplars:            []prompb.Exemplar{},
            },
          },
        },
      },
    }
    ```