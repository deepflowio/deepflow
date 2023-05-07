# Prometheus PromQL 文档

## 查询流程

1. Instant 查询：[promql.go](./service/promql.go) 中 PromQueryExecute 方法
2. Range 查询：[promql.go](./service/promql.go) 中 PromQueryRangeExecute 方法
3. 在两种查询中，由 NewInstantQuery/NewRangeQuery 方法传入 PromQL，由 Prometheus Engine 解析并在 [queryable.go](./service/queryable.go) 的 Select 方法中获得语法树，并在 `hints *storage.SelectHints, matchers ...*labels.Matcher` 参数中获取具体内容。
4. 在 [queryable.go](./service/queryable.go) 中，由 remote.ToQuery 方法生成 RemoteRead 结构，并执行 PromReaderExecute 方法进行查询。
5. 在 [remote_read.go](./service/remote_read.go) 中，PromReaderTransToSQL 方法将 RemoteRead 请求结构翻译成 Querier SQL。（请求结构参考 [Prometheus RemoteRead API 文档](https://github.com/prometheus/prometheus/blob/main/prompb/remote.proto#L31)）
6. 在 [clickhouse.go](../../engine/clickhouse/clickhouse.go) 中，由 ExecuteQuery 执行查询。
7. 返回：在 [remote_read.go](./service/remote_read.go) 中由 RespTransToProm 方法将 Querier 结果转换为 [RemoteRead 返回结构](https://github.com/prometheus/prometheus/blob/main/prompb/remote.proto#L62)。
8. 其余计算（如函数聚合、其他的过滤）由 Prometheus Engine 代码完成

## Metric 解析逻辑

其中 `{metricsName}` 为 [Querier 的 GetMetrics 函数](../../engine/clickhouse/metrics/metrics.go) 所返回的指标量名称。

解析规则：

| db                                         | metrics                                          |
|--------------------------------------------|--------------------------------------------------|
| `flow_log`, `event`, `deepflow_system`     | `{db}__{table}__{metricsName}`                   |
| `flow_metrics`                             | `{db}__{table}__{metricsName}__{datasource}`     |
| `ext_metrics` (ingested by prometheus)     | `ext_metrics__metrics__prometheus_{metricsName}` |
| `ext_metrics` (TODO, ingested by influxdb) | `ext_metrics__metrics__influxdb_{metricsName}`   |

其中，prometheus 写入的指标量, 因为需要支持 prometheus 页面的 RemoteRead, 所以直接使用指标量名称裸查, 并且去掉由 ext_common 中 getExtMetrics 所增加的 `metrics.` 前缀。Querier 针对 `ext_metrics` 查询的逻辑与其他 db 不同，查询时需要将 `table` 设置为 `prometheus.{metricsName}`, 查询的 metricsName 需携带 `metrics.` 前缀（如：`select metrics.node_cpu_seconds_total from prometheus.node_cpu_seconds_total`）

## PromQL 实现完整性测试

使用 Prometheus 提供的测试 Repo: https://github.com/prometheus/compliance，并按照以下步骤执行测试。
Depends on: Git/Golang Runtime
```bash
git clone https://github.com/prometheus/compliance.git
cd ./compliance/promql/
go build -o ./cmd/promql-compliance-tester .
```
测试命令：
```bash
./promql-compliance-tester --config-file=promql-deepflow-metrics-query.yaml
```

## 附：Prometheus RemoteRead API 文档

### 请求(Request)

- URL: /api/v1/prom/read
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

### 返回(Response)

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