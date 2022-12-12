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
  flow_metrics.decoder
  flow_log.decoder.1["flow_log.decoder"]
  flow_log.decoder.2["flow_log.decoder"]
  flow_log.decoder.3["flow_log.decoder"]
  flow_log.decoder.4["flow_log.decoder"]
  ext_metrics.decoder.1["ext_metrics.decoder"]
  ext_metrics.decoder.2["ext_metrics.decoder"]
  ext_metrics.decoder.3["ext_metrics.decoder"]
  ingester.queue.1(["queue"])
  ingester.queue.2(["queue"])
  ingester.queue.3(["queue"])
  flow_metrics.dbwriter
  flow_log.dbwriter
  ext_metrics.dbwriter
end

Kernel -->|cBPF/AF_PACKET| Dispatcher
Dispatcher --> agent.queue.1 -->|Metrics| UniformSender.1 -->|"tcp(pb)"| flow_metrics.decoder -->|Document| ingester.queue.1 --> flow_metrics.dbwriter
Dispatcher --> agent.queue.2 -->|L4FlowLog| UniformSender.2 -->|"tcp(pb)"| flow_log.decoder.1 -->|L4FlowLog| ingester.queue.2 --> flow_log.dbwriter
Dispatcher --> agent.queue.3 -->|L7FlowLog| UniformSender.3 -->|"tcp(pb)"| flow_log.decoder.2 -->|L7FlowLog| ingester.queue.2

Kernel -->|eBPF| EbpfCollector
EbpfCollector --> agent.queue.3

otel-collector -->|OTLP| IntegrationCollector
otel-javaagent/sdk -->|OTLP| IntegrationCollector
IntegrationCollector --> agent.queue.4 -->|"zip(OTLP)"| UniformSender.4 -->|"tcp(zip(OTLP))"| flow_log.decoder.3 -->|L7FlowLog| ingester.queue.2
IntegrationCollector --> agent.queue.5 -->|OTLP| UniformSender.5 -->|"tcp(OTLP)"| flow_log.decoder.4 -->|L7FlowLog| ingester.queue.2

prometheus-server -->|prom-pb| IntegrationCollector
telegraf -->|influxdb| IntegrationCollector
IntegrationCollector --> agent.queue.6 -->|prom-pb| UniformSender.6 -->|"tcp(prom-pb)"| ext_metrics.decoder.1 -->|ExtMetrics| ingester.queue.3 --> ext_metrics.dbwriter
IntegrationCollector --> agent.queue.7 -->|influxdb| UniformSender.7 -->|"tcp(influxdb)"| ext_metrics.decoder.2 -->|ExtMetrics| ingester.queue.3

XXX -->|XXXCounter| StatsdClient -->|"tcp(pb)"| ext_metrics.decoder.3 -->|ExtMetrics| ingester.queue.3

flow_metrics.dbwriter -->|flow_metrics| ClickHouse
flow_log.dbwriter -->|flow_log| ClickHouse
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

subgraph ingester.flow_metrics
  direction LR
  flow_metrics.receiver --> flow_metrics.queue([queue]) --> flow_metrics.decoder
end

subgraph ingester.flow_log
  direction LR
  flow_log.receiver --> flow_log.([queue]) --> flow_log.decoder --> throttler
end

subgraph ingester.ext_metrics
  direction LR
  ext_metrics.receiver --> ext_metrics.([queue]) --> ext_metrics.decoder
end
```

# 2. Meta Collection

```mermaid
flowchart TD

subgraph K8s.Node.1
  APIServer[(k8s-apiserver)]
  PodMAC.1[(PodMAC)]
  NodeMAC.1[(NodeMAC)]

  subgraph deepflow-agent.k8s.1
    subgraph PlatformSynchronizer.1[PlatformSynchronizer]
      ActivePoller.1[ActivePoller]
      PassivePoller.1[PassivePoller]
    end

    subgraph ApiWatcher
      ResourceWatcher
    end
  end
end

subgraph K8s.Node.2
  PodMAC.2[(PodMAC)]
  NodeMAC.2[(NodeMAC)]

  subgraph deepflow-agent.k8s.2
    subgraph PlatformSynchronizer.2[PlatformSynchronizer]
      ActivePoller.2[ActivePoller]
      PassivePoller.2[PassivePoller]
    end
  end
end

subgraph Host.1
  HostInfo.1[(HostInfo)]

  subgraph deepflow-agent.host.1
    PlatformSynchronizer.3[PlatformSynchronizer]
  end
end

subgraph Host.2
  HostInfo.2[(HostInfo)]

  subgraph deepflow-agent.host.2
    PlatformSynchronizer.4[PlatformSynchronizer]
  end
end

subgraph deepflow-server.1
  controller.genesis.1[controller.genesis]
  controller.cloud.1[controller.cloud]
  controller.recorder.1[controller.recorder]
  queue.1(queueu)
  ingester.event.1[ingester.event]
  controller.tagrecoreder

  controller.genesis.1 -->|"k8s & host meta"| controller.cloud.1 -->|meta| controller.recorder.1 -->|event| queue.1 --> ingester.event.1
end

subgraph deepflow-server.2
  controller.genesis.2[controller.genesis]
  controller.cloud.2[controller.cloud]
  controller.recorder.2[controller.recorder]
  queue.2(queueu)
  ingester.event.2[ingester.event]

  controller.genesis.2 -->|"k8s & host meta"| controller.cloud.2 -->|meta| controller.recorder.2 -->|event| queue.2 --> ingester.event.2
end

APIServer -->|"list, watch"| ResourceWatcher
ApiWatcher -->|gRPC.KubernetesAPISync| controller.genesis.1
NodeMAC.1 -->|"ip"| PlatformSynchronizer.1 -->|gRPC.GenesisSync| controller.genesis.1
PodMAC.1 -->|"setns, ip (w/ SYS_ADMIN)"| ActivePoller.1
PodMAC.1 -->|"AF_PACKET (w/o SYS_ADMIN)"| PassivePoller.1

NodeMAC.2 -->|"ip"| PlatformSynchronizer.2 -->|gRPC.GenesisSync| controller.genesis.2
PodMAC.2 -->|"setns, ip (w/ SYS_ADMIN)"| ActivePoller.2
PodMAC.2 -->|"AF_PACKET (w/o SYS_ADMIN)"| PassivePoller.2

HostInfo.1 -->|"hostname, ip"| PlatformSynchronizer.3 -->|gRPC.GenesisSync| controller.genesis.1
HostInfo.2 -->|"hostname, ip"| PlatformSynchronizer.4 -->|gRPC.GenesisSync| controller.genesis.2

CloudAPI[(CloudAPI)] -->|cloud meta| controller.cloud.2

controller.genesis.1 <-->|"exchange & merge"| controller.genesis.2

controller.recorder.1 -->|meta| MySQL.Meta[(MySQL Meta Tables)]
controller.recorder.2 -->|meta| MySQL.Meta

MySQL.Meta -->|meta| controller.tagrecoreder -->|tag| MySQL.Tag[(MySQL Tag Tables)]

MySQL.Tag -.->|sync| ClickHouse.1[(ClickHouse.1)]
MySQL.Tag -.->|sync| ClickHouse.2[(ClickHouse.2)]

ingester.event.1 -->|event| ClickHouse.1
ingester.event.2 -->|event| ClickHouse.2
```

# 3. Agent Registration

## 3.1. Agent on K8s Node

```mermaid
sequenceDiagram
    participant apiserver
    participant agent
    participant server.controller.trisolaris
    participant server.controller.genesis
    participant server.controller.cloud
    participant server.controller.recorder
    participant mysql

    Note right of agent: 1. get kubernetes-cluster-id
    activate agent
    agent ->> agent: load k8s-cluster-id from agent.yaml
    opt k8s-cluster-id is None
        agent ->> server.controller.trisolaris: gRPC.GetKubernetesClusterID(ca-md5)
        server.controller.trisolaris ->> server.controller.trisolaris: lookup k8s-cluster-id by ca-md5 in cache
        opt k8s-cluster-id is None
            server.controller.trisolaris ->> mysql: lookup k8s-cluster-id by ca-md5, if it does not exist, generate it.
        end
        server.controller.trisolaris ->> agent: k8s-cluster-id
    end
    deactivate agent

    Note right of agent: 2. sync K8s resources
    activate agent
    agent ->> server.controller.trisolaris: gRPC.Sync(k8s-cluster-id, node-ip, node-mac)
    server.controller.trisolaris ->> server.controller.trisolaris: Elect one K8s watcher agent for each K8s cluster
    alt is the K8s watcher
        server.controller.trisolaris ->> agent: kubernetes_api_enabled=true

        agent ->> apiserver: watch resource

        agent ->> server.controller.genesis: gRPC.KubernetesAPISync(k8s-cluster-id, k8s-resource-list)
        server.controller.genesis ->> server.controller.cloud: Node Info
        server.controller.cloud ->> server.controller.recorder: Node Info
        server.controller.recorder ->> mysql: insert pod_node table
    else is not the K8s watcher
        server.controller.trisolaris ->> agent: kubernetes_api_enabled=false
    end
    deactivate agent

    Note right of agent: 3. sync IP/MAC addresses
    activate agent
    agent ->> server.controller.genesis: gRPC.GenesisSync(k8s-cluster-id, local-ip/mac-list)
    server.controller.genesis ->> server.controller.cloud: Node IP/MAC
    server.controller.cloud ->> server.controller.recorder: Node IP/MAC
    server.controller.recorder ->> mysql: insert node mac into vinterface table
    server.controller.recorder ->> mysql: insert node ip into vinterface_ip table (LAN IP)
    server.controller.recorder ->> mysql: insert node ip into ip_resource table (WAN IP)
    deactivate agent

    Note right of agent: 4. agent (vtap) registration
    activate agent
    agent ->> server.controller.trisolaris: gRPC.Sync(k8s-cluster-id, node-ip, node-mac)
    server.controller.trisolaris ->> mysql: lookup node-mac in vinterface table
    server.controller.trisolaris ->> mysql: lookup node-ip in vinterface_ip/ip_resource table
    server.controller.trisolaris ->> server.controller.trisolaris: match vtap and k8s-node
    server.controller.trisolaris ->> mysql: inesrt vtap table, return vtap_id
    server.controller.trisolaris ->> mysql: lookup agent_config by vtap-group-id
    server.controller.trisolaris ->> agent: vtap_id, agent_config
    deactivate agent

    Note right of agent: 5. subsequent agent requests
    activate agent
    agent ->> server.controller.trisolaris: gRPC.Sync(vtap_id)
    server.controller.trisolaris ->> agent: agent_config
    deactivate agent
```

## 3.2. Agent on Legacy Host

```mermaid
sequenceDiagram
    participant agent
    participant server.controller.trisolaris
    participant server.controller.genesis
    participant server.controller.cloud
    participant server.controller.recorder
    participant mysql

    Note right of agent: 1. agent (vtap) first request
    activate agent
    agent ->> server.controller.trisolaris: gRPC.Sync(host-ip, host-mac)
    server.controller.trisolaris ->> mysql: lookup host-mac in vinterface table
    server.controller.trisolaris ->> mysql: lookup host-ip in vinterface_ip/ip_resource table
    server.controller.trisolaris ->> server.controller.trisolaris: unknown agent, without k8s-cluster-id
    server.controller.trisolaris ->> agent: platform_enabled=true
    deactivate agent

    Note right of agent: 2. sync IP/MAC addresses
    activate agent
    agent ->> server.controller.genesis: gRPC.GenesisSync(hostname, local-ip/mac-list)
    server.controller.genesis ->> server.controller.cloud: Host Info
    server.controller.cloud ->> server.controller.recorder: Host Info
    server.controller.recorder ->> mysql: insert host into vm table
    server.controller.recorder ->> mysql: insert host mac into vinterface table
    server.controller.recorder ->> mysql: insert host ip into vinterface_ip table (LAN IP)
    server.controller.recorder ->> mysql: insert host ip into ip_resource table (WAN IP)
    deactivate agent

    Note right of agent: 3. agent registration
    activate agent
    agent ->> server.controller.trisolaris: gRPC.Sync(host-ip, host-mac)
    server.controller.trisolaris ->> mysql: lookup host-mac in vinterface table
    server.controller.trisolaris ->> mysql: lookup host-ip in vinterface_ip/ip_resource table
    server.controller.trisolaris ->> server.controller.trisolaris: match vtap and host (vm)
    server.controller.trisolaris ->> mysql: inesrt vtap table, return vtap_id
    server.controller.trisolaris ->> mysql: lookup agent_config by vtap-group-id
    server.controller.trisolaris ->> agent: vtap_id, agent_config
    deactivate agent

    Note right of agent: 4. subsequent agent requests
    activate agent
    agent ->> server.controller.trisolaris: gRPC.Sync(vtap_id)
    server.controller.trisolaris ->> agent: agent_config
    deactivate agent
```

## 3.3. Agent on Cloud Host

# 4. AutoTagging

TODO

# 5. Agent Management

TODO
