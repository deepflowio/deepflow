# 最新提交概要（2026-02-11）

## 基本信息
- Commit: e7a6b22c2cd0a8a928d4f56b008b085e6a0b77d6
- 标题: feat: refactor recorder cache tool
- 作者: zhengya
- 提交时间: 2026-02-11 14:28:28 +0800

## 核心变更概览
- 新增基于 YAML 配置的 cache tool 代码生成器，集中在 generator 目录。
- 引入统一的生成模板，覆盖数据结构、集合操作、扩展点、MapSet 等通用能力。
- 新增多种资源的 cache tool 实现与对应配置，开始以配置驱动的方式生成缓存结构。
- 资源类型枚举更新以匹配新资源。

## 关键文件解读
### 1) 生成器入口
- 生成器文件：[server/controller/recorder/generator/generator.go](server/controller/recorder/generator/generator.go)
- 关键能力：
  - 读取 YAML 配置、适配字段、自动生成 CamelName / PublicCamelName。
  - 支持扩展文件（*_ext.go）解析 import 与字段扩展内容。
  - 支持单文件、通配符、多文件与 --all 批量生成。
  - 生成后自动执行 go fmt 与 goimports。

### 2) 统一模板
- 模板文件：[server/controller/recorder/cache/tool/gen.go.tpl](server/controller/recorder/cache/tool/gen.go.tpl)
- 关键能力：
  - 生成 resource cache struct、校验与字段 getter/setter。
  - 统一 collection 行为与 key 字段映射。
  - 支持扩展字段与 collection 扩展，增强可插拔性。
  - 对 plural 字段支持 mapset 操作接口。

### 3) 资源配置示例（从新增 YAML 中抽取）
- pod_node（[server/controller/recorder/generator_config/pod_node.yaml](server/controller/recorder/generator_config/pod_node.yaml)）
  - 包含 domain、region、az、vpc、podCluster、vm 等关联信息。
  - vmID 设置了 has_setter，支持后续变更与补齐。
- process（[server/controller/recorder/generator_config/process.yaml](server/controller/recorder/generator_config/process.yaml)）
  - 声明 has_extension 与 collection_extension，允许拓展字段与集合行为。
  - 建模 deviceType / deviceID / pod / vm / vpc 关系。
- vinterface（[server/controller/recorder/generator_config/vinterface.yaml](server/controller/recorder/generator_config/vinterface.yaml)）
  - 引入 is_custom 字段 deviceName，典型的扩展字段落点。
  - 关联 region / network / vpc / device 等基础维度。

## 影响范围
- 新增大量 tool 层缓存结构与集合能力（[server/controller/recorder/cache/tool](server/controller/recorder/cache/tool)）。
- 资源类型枚举扩展（[server/controller/common/resource_type.go](server/controller/common/resource_type.go)）。
- 生成器与配置成为新增资源接入的主要入口。

## 提交的核心变化与意图
### 架构演进：从手工维护到配置驱动
本次提交**并非替换** [data_set.go](server/controller/recorder/cache/tool/data_set.go)（它仅删除了 7 行代码，几乎无变化），而是在 tool 包下**新增了一套并行的、可生成的缓存工具体系**：
- **新增 3900+ 行代码**：包括 collection.go（通用集合框架）、tool.go（统一入口）及 40+ 个资源的生成文件
- **DataSet 保留原样**：继续以手工方式维护 `lcuuidToID`、`idToInfo` 等映射表及其 Add/Delete/Get 方法
- **Tool/Collection 新体系**：通过 YAML 配置 + 模板生成，提供统一的缓存结构与操作语义

### 新旧体系对比
| 特性 | DataSet（旧）| Tool/Collection（新）|
|------|-------------|---------------------|
| 维护方式 | 手工编写字段与方法 | YAML 配置驱动生成 |
| 映射结构 | 分散的 map（如 `vmLcuuidToID`、`vmIDToInfo`） | 统一的 Collection 封装（`lcuuidToItem`、`idToItem`） |
| 扩展方式 | 直接修改源码 | `*_ext.go` 扩展文件 + `CollectionExtender` 接口 |
| 回源逻辑 | 各资源独立实现 | 集合层统一 `GetOrLoadByLcuuid` |
| 接入成本 | 手写所有逻辑 | 新增 YAML 即可 |

### 并行运行的意图
这是一次**渐进式重构**：
1. 新增资源优先使用 Tool/Collection 体系（如新增的 30+ 个资源类型）
2. DataSet 暂时保留以兼容现有代码，避免大规模改动
3. 未来可逐步将 DataSet 中的资源迁移至 Tool 体系，最终完成统一

## 后续任务
1) 在 CI 中加入生成器一致性校验（如：yaml -> 生成文件 diff），避免手改产物与配置不一致。
2) 为关键资源增加最小化单元测试，覆盖 key 字段映射、GetOrLoad 行为、扩展字段注入。
3) 明确 goimports 依赖版本与可用性，避免生成失败导致 CI 误报。
4) 为 YAML 配置定义 schema 或 lint 规则，提前发现字段缺失或类型不一致问题。
5) 面向“bug 导致同 key 反复回源”场景，增加异常回源保护与告警：
  - 负缓存：对连续未命中 key 设置短 TTL，避免反复打 DB。
  - 单飞：同 key 并发回源只允许一次查询，避免放大。
  - 限速/熔断：同资源类型或 key 超阈值时降级返回，保护 DB。
  - 异常采样告警：记录连续回源次数与调用点，快速定位 bug。
  - 预热/刷新优化：对高频资源提前加载，降低关键路径回源。

## 评估与可优化点
- 必要性：本次提交将 cache tool 从手工维护转为配置驱动生成，能显著降低重复代码与维护成本，并统一缓存语义与扩展方式。
- 可优化点：
  1) 生成器增加版本锁与可重复生成标识，避免模板升级造成不透明改动。
  2) 明确生成产物与扩展文件边界，仅允许字段/钩子扩展，限制业务逻辑混入。
  3) 在集合层统一回源、日志与错误策略，减少散落实现的不一致。
  4) 降低对 goimports 的硬依赖（可选），避免在环境缺失时阻塞生成。
