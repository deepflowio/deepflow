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