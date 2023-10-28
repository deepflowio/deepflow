<p align="center">
  <img src="./docs/deepflow-logo.png" alt="DeepFlow" width="300" />

  <p align="center">Instant Observability for Cloud-Native Applications</p>
  <p align="center">Zero Code, Full Stack, eBPF & Wasm</p>
</p>
<p align="center">
    <a href="https://zenodo.org/badge/latestdoi/448599559"><img src="https://zenodo.org/badge/448599559.svg" alt="DOI"></a>
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/deepflowio/deepflow"> </a>
    <img alt="docker pulls" src="https://img.shields.io/docker/pulls/deepflowce/deepflow-agent?color=green?label=docker pulls"> </a>
    <img alt="License" src="https://img.shields.io/github/license/deepflowio/deepflow?color=purple"> </a>
</p>

-------------

English | [简体中文](./README-CN.md)

# What is DeepFlow

The DeepFlow open-source project aims to provide deep observability for complex cloud infrastructures and cloud-native applications. DeepFlow implemented **Zero Code** data collection with eBPF for metrics, distributed tracing, request logs and function profiling, and is further integrated with **SmartEncoding** to achieve **Full Stack** correlation and efficient access to all observability data. With DeepFlow, cloud-native applications automatically gain deep observability, removing the heavy burden of developers continually instrumenting code and providing monitoring and diagnostic capabilities covering everything from code to infrastructure for DevOps/SRE teams.

# Key Features

- **Universal Map for Any Service**: DeepFlow provides a universal map with **Zero Code** by eBPF for production environments, including your services in any language, third-party services without code and all cloud-native infrastructure services. In addition to analyzing common protocols, Wasm plugins are supported for your private protocols. **Full Stack** golden signals of applications and infrastructures are calculated, pinpointing performance bottlenecks at ease.
- **Distributed Tracing for Any Request**: **Zero Code** distributed tracing powered by eBPF supports applications in any language and infrastructures including gateways, service meshes, databases, message queues, DNS and NICs, leaving no blind spots. **Full Stack** network performance metrics and file I/O events are automatically collected for each Span. Distributed tracing enters a new era: Zero Instrumentation.
- **Continuous Profiling for Any Function**: DeepFlow collects profiling data at a cost of below 1% with **Zero Code**, plots OnCPU/OffCPU function call stack flame graphs, locates **Full Stack** performance bottleneck in application, library and kernel functions, and automatically relates them to distributed tracing data. DeepFlow can even analyze code performance through network profiling under old version kernels (2.6+).
- **Seamless Integration with Popular Stack**: DeepFlow can serve as storage backed for Prometheus, OpenTelemetry, SkyWalking and Pyroscope. It also provides **SQL, PromQL and OLTP** APIs to work as data source in popular observability stacks. It injects meta tags for all observability signals including cloud resource, K8s container, K8s labels, K8s annotations, CMDB business attributes, etc., eliminating data silos.
- **Performance 10x ClickHouse**: **SmartEncoding** injects standardized and pre-encoded meta tags into all observability data, reducing storage overhead by 10x compared to ClickHouse String or LowCard method. Custom tags and observability data are stored separately, making tags available for almost unlimited dimensions and cardinalities with uncompromised query experience like **BigTable**.

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

## DeepFlow Enterprise

You can visit the [DeepFlow Enterprise Demo](https://deepflow.yunshan.net/), currently available in Chinese only.

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

# Honors

- The paper [Network-Centric Distributed Tracing with DeepFlow: Troubleshooting Your Microservices in Zero Code](https://dl.acm.org/doi/10.1145/3603269.3604823) has been accepted by ACM SIGCOMM 2023.
- DeepFlow enriches the <a href="https://landscape.cncf.io/?selected=deep-flow">CNCF CLOUD NATIVE Landscape</a>.
- DeepFlow enriches the <a href="https://ebpf.io/applications#deepflow">eBPF Project Landscape</a>.
