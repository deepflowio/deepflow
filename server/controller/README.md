# 代码架构

### controllermaster

- 对外提供API
  - 云平台相关API
  - 控制器/数据节点/采集器相关API
- 健康检查
- 授权检查

### controller

- router、service
  - 对外提供API
- synchronizer
  - 推送平台/采集器配置数据
  - 控制器/数据节点/采集器自动发现
- manager
  - 负责各云平台task的更新和生命周期管理，task包括cloud（云平台信息收集和组装）和record（数据库记录）
- recorder
  - 记录资源数据
  - 发送资源变更事件
- tagrecorder
  - 记录字典标签数据
- cloud
  - 各类云平台的收集和组装
  - kubernetes_gather
    - 由各云平台按需启动，向其（包括kubernetes）提供K8s资源数据（不考虑云平台业务逻辑）
