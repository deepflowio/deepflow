![MetaFlow](./docs/metaflow-logo.svg)
=====================================

English | [简体中文](./README-CN.md)

# What is MetaFlow

MetaFlow is a highly automated observability platform open sourced by [YUNSHAN Network Inc.](https://yunshan.net). It is a full stack, full span and high-performance data engine built for cloud-native observability application developers. With new technologies such as eBPF, WASM and OpenTelemetry, MetaFlow innovatively implements core mechanisms such as AutoTracing, AutoMetrics, AutoTagging and SmartEncoding, helping developers to improve the automation level of code injection, reducing the maintanence complexity of the observability platform. With the programmability and open API of MetaFlow, developers can quickly integrate it into their observability stack.

# Key Features

- **Any Stack**: With the AutoMetrics mechanism implemented by AF\_PACKET, BPF and eBPF technologies, MetaFlow can automatically collect RED (Request, Error, Delay) performance metrics of any application, down to every application call, covering all software technologie stacks from application to infrastructure. In cloud-native environments, the AutoTagging mechanism of MetaFlow automatically discovers the attributes of services, instances and APIs, and automatically injects rich tags into each observation data, thereby eliminating data silos and releasing data drill-down capabilities.
- **End to End**: MetaFlow innovatively implements the AutoTracing mechanism using eBPF technology. It automatically traces the distributed request chain of any microservice and infrastructure service in cloud-native environments. On this basis, through data integration with OpenTelemetry, MetaFlow automatically associates eBPF Event with OTel Span to achieve complete full stack and full span tracing, eliminating any tracing blind spots.
- **High Performance**: The innovative SmartEncoding tag injection mechanism of MetaFlow can improve the storage performance of tag data by 10 times, no more high-based tags and data sampling anxiety. MetaFlow Agent is implemented in Rust for extreme processing performance and memory safety. MetaFlow Server is implemented in Golang, and rewrites standard library map and pool for a nearly 10x performance in data query and memory application.
- **Programmability**: MetaFlow supports parsing HTTP, Dubbo, MySQL, Redis, Kafka and DNS at the moment, and will iterate to support more application protocols. In addition, MetaFlow provides a programmable interface based on WASM technology, allowing developers to parse private protocols quickly, and can be used to construct business analysis capabilities for specific scenarios, such as 5GC signaling analysis, financial transaction analysis, vehicle computer communication analysis, etc.
- **Open Interface**: MetaFlow embraces the open source community, supports a wide range of observability data sources, and uses AutoTagging and SmartEncoding to provide high-performance, unified tag injection capabilities. MetaFlow has a plugable database interface, developers can freely add and replace the most suitable database. MetaFlow provides a unified standard SQL query capability for all observability data upwards, which is convenient for users to quickly integrate into their own observability platform, and also provides the possibility of developing dialect QLs on this basis.
- **Easy to Maintain**: MetaFlow only consists of two components, Agent and Server, hiding the complexity within the process and reduces the maintenance difficulty to the extreme. The MetaFlow Server cluster can manage Agents in multiple resource pools, heterogeneous resource pools and cross-region/cross-AZ resource pools in a unified manner, and can achieve horizontal scaling and load balancing without any external components.

# Documentation

Detailed information is on [our website](https://deepflow.yunshan.net/metaflow-docs/).

# Software Architecture

MetaFlow consists of two processes, Agent and Server. An Agent runs in each K8s node, virtual machine and physical bare metal, and is responsible for AutoMetrics and AutoTracing data collection of all application processes on the server. Server runs in a K8s cluster and provides Agent management, data tag injection, data writing and data query services.

![MetaFlow Architecture](./docs/metaflow-architecture.png)

# Milestones

MetaFlow was born from DeepFlow, a commercial product of Yunshan Networks, which has now developed to v6.1.0. There is still some code refactor work to be done. We plan to release the first downloadable version in June 2022, with the following features:
- [x] AutoMetrics capability based on eBPF, BPF+AF\_PACKET
- [x] HTTP 1/2/S, Dubbo, MySQL, Redis, Kafka, DNS application protocol parsing capabilities based on eBPF
- [x] AutoTracing distributed span tracing capability based on eBPF, supports synchronous concurrency model and Native thread scheduling model
- [x] AutoTagging capability to automatically synchronize K8s apiserver and inject resource and service tags
- [x] High-performance SmartEncoding tag injection capability
- [x] Integration capabilities for Prometheus and OpenTelemetry
- [x] Use ClickHouse as default database
- [x] Use Grafana as default visualization component

There are many exciting features waiting for us to develop together with the community, including:
- AutoMetrics & AutoTracing
  - [ ] Support parsing more application protocols
  - [ ] Enhanced integration with OpenTelemetry, plugged into OTel Tracer API via eBPF
  - [ ] Support more automated AutoTracing capabilities, explore support for asynchronous concurrency models and coroutine scheduling models
  - [ ] AutoMetrics capability based on BPF+Winpcap
  - [ ] Support Agent to actively dial test to obtain Metrics
  - [ ] Supports the use of eBPF to collect On/Off CPU flame graphs, providing zero-intrusion Continue Profile capability
- AutoTagging & SmartEncoding
  - [ ] Automatically synchronize and inject process label information in a non-container environment
  - [ ] Synchronize service registry, automatically inject service and API property information
- Agent
  - [ ] Programmable application protocol parsing capability that supports WASM
  - [ ] Integrate SkyWalking, Sentry, Telegraf, Loki and more data sources
  - [ ] Support running on Android operating system (smart car scene)
  - [ ] Support Agent running in Serverless Pod in the form of Sidecar
- Server
  - [ ] Support for more analytical databases
  - [ ] Support for more QL dialects

# Acknowledgments

- Thanks [eBPF](https://ebpf.io/), a revolutionary Linux kernel technology.
