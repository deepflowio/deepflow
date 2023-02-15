<p align="center">
  <img src="./docs/deepflow-logo.png" alt="DeepFlow" width="300" />

  <p align="center">DeepFlow is an automated observability platform for cloud-native developers.</p>
</p>
<p align="center">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/deepflowio/deepflow"> </a>
    <img alt="docker pulls" src="https://img.shields.io/docker/pulls/deepflowce/deepflow-agent?color=green?label=docker pulls"> </a>
    <img alt="License" src="https://img.shields.io/github/license/deepflowio/deepflow?color=purple"> </a>
</p>

-------------

English | [简体中文](./README-CN.md)

# What is DeepFlow

DeepFlow is a **highly automated** observability platform for cloud-native developers. Using new technologies such as **eBPF**, WASM, and OpenTelemetry, DeepFlow innovatively implements core mechanisms such as **AutoTracing**, **AutoMetrics**, **AutoTagging**, and **SmartEncoding**, which greatly avoids code instrumentation and significantly reduces the resource overhead of back-end data warehouses. With the programmability and open API of DeepFlow, developers can quickly integrate it into their own observability stack.

# Key Features

- **Any Stack**: With the **AutoMetrics** mechanism implemented by **eBPF** and cBPF, DeepFlow can automatically collect RED (Request, Error, Delay) performance metrics of any application, down to every request, covering all software technologie stacks from application to infrastructure. In cloud-native environments, the **AutoTagging** mechanism automatically discovers the attributes of services, instances and APIs, and automatically injects rich tags into each observability data, thereby eliminating data silos and releasing data drill-down capabilities.
- **End to End**: DeepFlow innovatively implements the **AutoTracing** mechanism using **eBPF** technology. It automatically traces the distributed request of any application and infrastructure service in cloud-native environments. On this basis, by integrating and automatically correlating data from OpenTelemetry, DeepFlow implements a complete full-stack, full-path distributed tracing, eliminating all blind spots.
- **High Performance**: The innovative **SmartEncoding** tag injection mechanism can improve the storage performance by 10 times, no more high-cardinality and sampling anxiety. DeepFlow Agent is implemented in Rust for extreme processing performance and memory safety. DeepFlow Server is implemented in Golang, and rewrites standard library map and pool for a nearly 10x performance in data query and memory GC.
- **Programmability**: DeepFlow supports collect HTTP(S), Dubbo, MySQL, PostgreSQL, Redis, Kafka, MQTT and DNS at the moment, and will iterate to support more application protocols. In addition, DeepFlow provides a programmable interface based on WASM technology, allowing developers to add private protocols quickly, and can be used to construct business analysis capabilities for specific scenarios, such as 5GC signaling analysis, financial transaction analysis, vehicle computer communication analysis, etc.
- **Open Interface**: DeepFlow embraces the open source community, supports a wide range of observability data sources, and uses AutoTagging and SmartEncoding to provide high-performance, unified tag injection capabilities. DeepFlow has a plugable database interface, developers can freely add and replace the most suitable database. DeepFlow provides a unified standard SQL query capability for all observability data, which is convenient for users to quickly integrate into their own observability platform.
- **Easy to Maintain**: The core of DeepFlow only consists of two components, Agent and Server, hiding the complexity within the process and reduces the maintenance difficulty to the extreme. The DeepFlow Servers can manage Agents in multiple kubernetes clusters, legacy hosts and cloud hosts in a unified manner, and can achieve horizontal scaling and load balancing without any external components.

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

DeepFlow Community Edition consists of two components, Agent and Server. An Agent runs in each K8s node, legacy host and cloud host, and is responsible for AutoMetrics and AutoTracing data collection of all application processes on the host. Server runs in a K8s cluster and provides Agent management, tag injection, data ingest and query services.

![DeepFlow Architecture](./docs/deepflow-architecture.png)

# Milestones

Here is our [future feature plan](https://deepflow.yunshan.net/docs/about/milestone/?from=github). Issues and Pull Requests are welcome.

# Contact Us

- Discord：Click [here](https://discord.gg/QJ7Dyj4wWM) to join our discussion.
- Twitter：[DeepFlow](https://twitter.com/deepflowio)
- WeChat Group：
<img src=./docs/wechat-group-keeper.png width=30% />

# Acknowledgments

- Thanks [eBPF](https://ebpf.io/), a revolutionary Linux kernel technology.
- Thanks [OpenTelemetry](https://opentelemetry.io/), provides vendor-neutral APIs to collect application telemetry data.

# Landscapes

- DeepFlow enriches the <a href="https://landscape.cncf.io/?selected=deep-flow">CNCF CLOUD NATIVE Landscape</a>.
- DeepFlow enriches the <a href="https://ebpf.io/applications#deepflow">eBPF Project Landscape</a>.
