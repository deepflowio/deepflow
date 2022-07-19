# 代码架构

### controller

- 支持各主流云/容器平台的资源抽象与对接
- 支持发送Meta资源给deepflow-ingester，用于观测数据进行Tag标记
- 支持管理10w量级deepflow-agent，可以做到单元化部署、多Region统一管理

### querier

- 提供一种面向Metrics、Tracing、Logging、Event的统一查询语言，打通各类观测数据。

### ingester

- 与deepflow-agent之间使用高性能私有协议，支持观测数据的快速传输和批量写入，避免依赖额外的消息队列。
- 支持对观测数据进行Tag增强，卸载deepflow-agent的本地计算压力和传输压力。
