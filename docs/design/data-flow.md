# 1. Data Collection

## 1.1. Overview

```mermaid
flowchart LR

subgraph deepflow-agent
  Dispatcher
  EbpfCollector
  IntegrationCollector
  XXX
  StatsdClient
  agent.queue.1(["queue"])
  agent.queue.2(["queue"])
  agent.queue.3(["queue"])
  agent.queue.4(["queue"])
  agent.queue.5(["queue"])
  agent.queue.6(["queue"])
  agent.queue.7(["queue"])
  UniformSender.1["UniformSender"]
  UniformSender.2["UniformSender"]
  UniformSender.3["UniformSender"]
  UniformSender.4["UniformSender"]
  UniformSender.5["UniformSender"]
  UniformSender.6["UniformSender"]
  UniformSender.7["UniformSender"]
end

subgraph deepflow-server.ingester
  roze.decoder
  stream.decoder.1["stream.decoder"]
  stream.decoder.2["stream.decoder"]
  stream.decoder.3["stream.decoder"]
  stream.decoder.4["stream.decoder"]
  ext_metrics.decoder.1["ext_metrics.decoder"]
  ext_metrics.decoder.2["ext_metrics.decoder"]
  ext_metrics.decoder.3["ext_metrics.decoder"]
  ingester.queue.1(["queue"])
  ingester.queue.2(["queue"])
  ingester.queue.3(["queue"])
  roze.dbwriter
  stream.dbwriter
  ext_metrics.dbwriter
end

Kernel -->|cBPF/AF_PACKET| Dispatcher
Dispatcher --> agent.queue.1 -->|Metrics| UniformSender.1 -->|"tcp(pb)"| roze.decoder -->|Document| ingester.queue.1 --> roze.dbwriter
Dispatcher --> agent.queue.2 -->|L4FlowLog| UniformSender.2 -->|"tcp(pb)"| stream.decoder.1 -->|FlowLogger| ingester.queue.2 --> stream.dbwriter
Dispatcher --> agent.queue.3 -->|L7FlowLog| UniformSender.3 -->|"tcp(pb)"| stream.decoder.2 -->|L7Logger| ingester.queue.2

Kernel -->|eBPF| EbpfCollector
EbpfCollector --> agent.queue.3

otel-collector -->|OTLP| IntegrationCollector
otel-javaagent/sdk -->|OTLP| IntegrationCollector
IntegrationCollector --> agent.queue.4 -->|"zip(OTLP)"| UniformSender.4 -->|"tcp(zip(OTLP))"| stream.decoder.3 -->|L7Logger| ingester.queue.2
IntegrationCollector --> agent.queue.5 -->|OTLP| UniformSender.5 -->|"tcp(OTLP)"| stream.decoder.4 -->|L7Logger| ingester.queue.2

prometheus-server -->|prom-pb| IntegrationCollector
telegraf -->|influxdb| IntegrationCollector
IntegrationCollector --> agent.queue.6 -->|prom-pb| UniformSender.6 -->|"tcp(prom-pb)"| ext_metrics.decoder.1 -->|ExtMetrics| ingester.queue.3 --> ext_metrics.dbwriter
IntegrationCollector --> agent.queue.7 -->|influxdb| UniformSender.7 -->|"tcp(influxdb)"| ext_metrics.decoder.2 -->|ExtMetrics| ingester.queue.3

XXX -->|XXXCounter| StatsdClient -->|"tcp(pb)"| ext_metrics.decoder.3 -->|ExtMetrics| ingester.queue.3

roze.dbwriter -->|flow_metrics| ClickHouse
stream.dbwriter -->|flow_log| ClickHouse
ext_metrics.dbwriter -->|ext_metrics| ClickHouse
```

## 1.2. From Dispatcher/EbpfCollector to UniformSender

```mermaid
flowchart LR

Dispatcher -->|MetaPacket| FlowGenerator
FlowGenerator -->|MetaPacket| FlowMap[(FlowMap)]
FlowGenerator -->|"TaggedFlow (1s)"| queue.1([queue])
queue.1 --> QuadrupleGenerator
QuadrupleGenerator --> SubQuadGen.1["SubQuadGen (1s)"]
SubQuadGen.1 -->|"AccumulatedFlow (1s)"| QuadrupleStash.1[("QuadrupleStash (1s)")]
SubQuadGen.1 -->|QuadrupleConnections| ConcurrentConnection.1[("ConcurrentConnection (1s)")]
SubQuadGen.1 -->|"AccumulatedFlow (1s)"| queue.2([queue]) --> Collector.1[Collector] -->|"Metrics(Document)"| queue.3([queue]) --> UniformSender.1[UniformSender]
QuadrupleGenerator --> SubQuadGen.2["SubQuadGen (1m)"]
SubQuadGen.2 -->|"AccumulatedFlow (1s)"| QuadrupleStash.2[("QuadrupleStash (1m)")]
SubQuadGen.2 -->|QuadrupleConnections| ConcurrentConnection.2[("ConcurrentConnection (1m)")]
SubQuadGen.2 -->|"AccumulatedFlow (1m)"| queue.4([queue]) --> Collector.2[Collector] -->|"Metrics(Document)"| queue.5([queue]) --> UniformSender.1
QuadrupleGenerator --> queue.6([queue]) --> FlowAggr -->|"TaggedFlow (1m)"| throttler -->|"L4FlowLog(TaggedFlow)"| queue.7([queue]) --> UniformSender.2[UniformSender]

FlowGenerator -->|MetaAppProto| queue.8([queue]) --> AppProtoLogsParser -->|AppProtoLogsData| throttler.1[throttler] -->|"L7FlowLog(AppProtoLogsData)"| queue.9([queue]) --> UniformSender.3[UniformSender]

EbpfCollector -->|MetaPacket| queue.10([queue]) --> EbpfRunner -->|AppProtoLogsData| SessionAggr --> throttler.2[throttler] -->|"L7FlowLog(AppProtoLogsData)"| queue.9
```

## 1.3. Decoders In deepflow-server.ingester

```mermaid
flowchart TD

subgraph ingester.roze
  direction LR
  roze.receiver --> roze.queue([queue]) --> roze.decoder
end

subgraph ingester.stream
  direction LR
  stream.receiver --> stream.([queue]) --> stream.decoder --> throttler
end

subgraph ingester.ext_metrics
  direction LR
  ext_metrics.receiver --> ext_metrics.([queue]) --> ext_metrics.decoder
end
```

# 2. Meta Collection

TODO

# 3. AutoTagging

TODO

# 4. Agent Management

TODO
