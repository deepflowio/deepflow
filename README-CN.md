![MetaFlow](./docs/metaflow-logo.svg)
=====================================

简体中文 | [English](./README.md)

# 什么是 MetaFlow

MetaFlow是[云杉网络](https://yunshan.net)开源的一款**高度自动化**的可观测性平台，是为云原生应用开发者建设可观测性能力而量身打造的全栈、全链路、高性能数据引擎。MetaFlow使用eBPF、WASM、OpenTelemetry等新技术，创新的实现了AutoTracing、AutoMetrics、AutoTagging、SmartEncoding等核心机制，帮助开发者提升埋点插码的自动化水平，降低可观测性平台的运维复杂度。利用MetaFlow的可编程能力和开放接口，开发者可以快速将其融入到自己的可观测性技术栈中。

# 六大主要特性

- **全栈**：MetaFlow使用AF\_PACKET、BPF、eBPF技术实现的**AutoMetrics**机制，可以自动采集任何应用的RED（Request、Error、Delay）性能指标，精细至每一次应用调用，覆盖从应用到基础设施的所有软件技术栈。在云原生环境中，MetaFlow的**AutoTagging**机制自动发现服务、实例、API的属性信息，自动为每个观测数据注入丰富的标签，从而消除数据孤岛，并释放数据的下钻能力。
- **全链路**：MetaFlow使用eBPF技术创新的实现了**AutoTracing**机制，在云原生环境中自动追踪任意微服务、基础设施服务的分布式调用链。在此基础上，通过与OpenTelemetry的数据集成，MetaFlow将eBPF Event与OTel Span自动关联，实现完整的全栈、全链路追踪，让追踪无盲点。
- **高性能**：MetaFlow创新的**SmartEncoding**标签注入机制，能够将标签数据的存储性能提升10倍，从此告别高基标签和数据采样焦虑。MetaFlow使用Rust实现Agent，拥有极致处理性能的同时保证内存安全。MetaFlow使用Golang实现Server，重写了Golang的map、pool基础库，数据查询和内存申请均有近10倍的性能提升。
- **可编程**：MetaFlow目前支持了对HTTP、Dubbo、MySQL、Redis、Kafka、DNS协议的解析，并将保持迭代增加更多的应用协议支持。除此之外，MetaFlow基于WASM技术提供了可编程接口，让开发者可以快速具备对私有协议的解析能力，并可用于构建特定场景的业务分析能力，例如5GC信令分析、金融交易分析、车机通信分析等。
- **开放接口**：MetaFlow拥抱开源社区，支持接收广泛的可观测数据源，并利用AutoTagging和SmartEncoding提供高性能、统一的标签注入能力。MetaFlow支持插件式的数据库接口，开发者可自由增加和替换最合适的数据库。MetaFlow向上为所有观测数据提供统一的标准SQL查询能力，便于使用者快速集成到自己的可观测性平台中，也提供了在此基础上继续开发方言QL的可能性。
- **易于维护**：MetaFlow仅由Agent、Server两个组件构成，将复杂度隐藏在进程内部，将维护难度降低至极致。MetaFlow Server集群可对多资源池、异构资源池、跨Region/跨AZ资源池中的Agent进行统一管理，且无需依赖任何外部组件即可实现水平扩展与负载均衡。

# 文档

详细信息请访问 [GitHub](https://github.com/metaflowys/docs/tree/main/zh/)，或者[文档站点](https://deepflow.yunshan.net/metaflow-docs/zh/)。

# 快速上手

## 部署 MetaFlow

请参考部署文档 [GitHub](https://github.com/metaflowys/docs/tree/main/zh/02-install)，[文档站点](https://deepflow.yunshan.net/metaflow-docs/zh/install/all-in-one/)。

## 体验 MetaFlow Demo

我们正在搭建了一个完整的 [MetaFlow Demo](https://demo.metaflow.yunshan.net/)，欢迎体验。

## 使用 DeepFlow Cloud

[DeepFlow Cloud](https://deepflow.yunshan.net/) 是我们的 MetaFlow 托管服务，目前处于测试阶段，仅支持中文。

# 软件架构

MetaFlow由Agent和Server两个进程组成。每个K8s容器节点、虚拟机或物理裸机中运行一个Agent，负责该服务器上所有应用进程的AutoMetrics和AutoTracing数据采集。Server运行在一个K8s集群中，提供Agent管理、数据标签注入、数据写入、数据查询服务。

![MetaFlow软件架构](./docs/metaflow-architecture.png)

# 里程碑

这里有我们[未来的 Feature 规划](https://github.com/metaflowys/docs/blob/main/zh/01-about/04-milestone.md)。欢迎 Issue 和 Pull Request。

# 致谢

- 感谢[eBPF](https://ebpf.io/)，革命性的Linux内核技术
- 感谢[OpenTelemetry](https://opentelemetry.io/)，提供了采集应用可观测性数据的标准API
