<p align="center">
  <img src="./docs/deepflow-logo.png" alt="DeepFlow" width="300" />

  <p align="center">DeepFlow is an automated observability platform for cloud-native developers..</p>
</p>
<p align="center">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/deepflowys/deepflow"> </a>
    <img alt="docker pulls" src="https://img.shields.io/docker/pulls/deepflowce/deepflow-agent?color=green?label=docker pulls"> </a>
    <img alt="License" src="https://img.shields.io/github/license/deepflowys/deepflow?color=yellow"> </a>
</p>

-------------

English | [简体中文](./README-CN.md)

# What is DeepFlow

DeepFlow is a highly automated observability platform open sourced by [YUNSHAN Networks Inc.](https://yunshan.net). It is a high-performance observability engine that supports end-to-end distributed tracing, built for cloud-native application developers, and for any software stack. With new technologies such as eBPF, WASM and OpenTelemetry, DeepFlow innovatively implements core mechanisms such as AutoTracing, AutoMetrics, AutoTagging and SmartEncoding, helping developers to improve the automation level of code injection, reducing the maintanence complexity of the observability platform. With the programmability and open API of DeepFlow, developers can quickly integrate it into their observability stack.

# Key Features

- **Any Stack**: With the **AutoMetrics** mechanism implemented by AF\_PACKET, BPF and eBPF technologies, DeepFlow can automatically collect RED (Request, Error, Delay) performance metrics of any application, down to every application call, covering all software technologie stacks from application to infrastructure. In cloud-native environments, the **AutoTagging** mechanism of DeepFlow automatically discovers the attributes of services, instances and APIs, and automatically injects rich tags into each observation data, thereby eliminating data silos and releasing data drill-down capabilities.
- **End to End**: DeepFlow innovatively implements the **AutoTracing** mechanism using eBPF technology. It automatically traces the distributed request chain of any microservice and infrastructure service in cloud-native environments. On this basis, through data integration with OpenTelemetry, DeepFlow automatically associates eBPF Event with OTel Span to achieve complete full stack and full span tracing, eliminating any tracing blind spots.
- **High Performance**: The innovative **SmartEncoding** tag injection mechanism of DeepFlow can improve the storage performance of tag data by 10 times, no more high-based tags and data sampling anxiety. DeepFlow Agent is implemented in Rust for extreme processing performance and memory safety. DeepFlow Server is implemented in Golang, and rewrites standard library map and pool for a nearly 10x performance in data query and memory application.
- **Programmability**: DeepFlow supports parsing HTTP, Dubbo, MySQL, Redis, Kafka and DNS at the moment, and will iterate to support more application protocols. In addition, DeepFlow provides a programmable interface based on WASM technology, allowing developers to parse private protocols quickly, and can be used to construct business analysis capabilities for specific scenarios, such as 5GC signaling analysis, financial transaction analysis, vehicle computer communication analysis, etc.
- **Open Interface**: DeepFlow embraces the open source community, supports a wide range of observability data sources, and uses AutoTagging and SmartEncoding to provide high-performance, unified tag injection capabilities. DeepFlow has a plugable database interface, developers can freely add and replace the most suitable database. DeepFlow provides a unified standard SQL query capability for all observability data upwards, which is convenient for users to quickly integrate into their own observability platform, and also provides the possibility of developing dialect QLs on this basis.
- **Easy to Maintain**: The core of DeepFlow only consists of two components, Agent and Server, hiding the complexity within the process and reduces the maintenance difficulty to the extreme. The DeepFlow Server cluster can manage Agents in multiple resource pools, heterogeneous resource pools and cross-region/cross-AZ resource pools in a unified manner, and can achieve horizontal scaling and load balancing without any external components.

# Documentation

For more information, please visit [the documentation website](https://deepflow.yunshan.net/docs/?from=github).

# Quick start

There are three editions of DeepFlow:
- DeepFlow Community: for developers
- DeepFlow Enterprise: for organizations, solving team collaboration problems
- DeepFlow Cloud: SaaS service, currently in beta

The DeepFlow Community Edition consists of the core components of the Enterprise Edition.

## DeepFlow Community

Please refer to [the deployment documentation](https://deepflow.yunshan.net/docs/install/all-in-one/?from=github).

At the same time, we have also built a complete [DeepFlow Community Demo](https://ce-demo.deepflow.yunshan.net/?from=github), welcome to experience it. Login account/password: deepflow/deepflow.

## DeepFlow Cloud

[DeepFlow Cloud](https://deepflow.yunshan.net/) is the fully-managed service of DeepFlow, currently in beta and only supports Chinese.

## DeepFlow Enterprise

[DeepFlow Enterprise](https://www.yunshan.net/products/deepflow.html) supports full-stack and end-to-end monitoring of hybrid cloud, covering containers, cloud servers, hosts, and NFV gateways, currently only supports Chinese, welcome to contact us for experience.

# Compile DeepFlow from Source

- [compile deepflow-agent](./agent/build.md)

# Software Architecture

DeepFlow Community consists of two processes, Agent and Server. An Agent runs in each K8s node, virtual machine and physical bare metal, and is responsible for AutoMetrics and AutoTracing data collection of all application processes on the server. Server runs in a K8s cluster and provides Agent management, data tag injection, data writing and data query services.

![DeepFlow Architecture](./docs/deepflow-architecture.png)

# Milestones

Here is our [future feature plan](https://deepflow.yunshan.net/docs/about/milestone/?from=github). Issues and Pull Requests are welcome.

# Join DeepFlow WeChat Group

Join the WeChat group，you can communicate with other users (in Chinese):

<img src=./docs/wechat-group-keeper.png width=30% />

# Acknowledgments

- Thanks [eBPF](https://ebpf.io/), a revolutionary Linux kernel technology.
- Thanks [OpenTelemetry](https://opentelemetry.io/), provides vendor-neutral APIs to collect application telemetry data.
