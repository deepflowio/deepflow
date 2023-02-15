# 如何增加采集器配置项

## 静态配置

- 修改 server 代码中的 StaticConfig 结构体，按需增加配置字段
  - [具体代码](https://github.com/deepflowio/deepflow/blob/main/server/controller/model/static_config.go#L20)
- 修改 server 代码中的采集器配置举例，在 static_config 中按需增加配置字段及描述信息
  - [具体代码](https://github.com/deepflowio/deepflow/blob/main/server/controller/model/vtap_group_config_example.go#L172)
