# Cache Tool Config 说明

## 1. 配置文件用途
本目录用于描述 recorder 的 cache tool 代码生成配置。每个 YAML 文件对应一个资源类型，生成器读取配置后输出 Go 代码到 [server/controller/recorder/cache/tool](server/controller/recorder/cache/tool)。

- 生成器入口：[server/controller/recorder/generator/generator.go](server/controller/recorder/generator/generator.go)
- 生成模板：[server/controller/recorder/cache/tool/gen.go.tpl](server/controller/recorder/cache/tool/gen.go.tpl)

## 2. 配置字段说明
### 顶层字段
- `name`：资源名称，使用 small_snake_case（例如 `pod_node`、`az`）。用于生成文件名，资源类型标识；使用统一标准转化为 PascalCase（例如 `PodNode`、`Az`），作为公有结构体及接口名称。
- `orm_name`：资源的 ORM 对象名称，需要与 ORM 定义保持一致。用于生成 db 相关的代码，如 `metadbmodel.PodNode`、`metadbmodel.AZ`。
- `cache_tool`：recorder 中的 cache/tool 模块。

### cache_tool 字段
- `enabled`：是否启用该模块的代码生成。
- `fields`：该资源 cache 结构体字段列表。
- `extensions`：扩展字段列表（可选）可选 `collection` 或 `struct`。
  - `collection`：集合包含扩展定义 `<PublicName>CollectionExt`，需要在 `<name>_ext.go` 中手动实现。
  - `struct`：结构体包含扩展定义 `<PublicName>Ext`，需要在 `<name>_ext.go` 中手动实现。

### fields 字段项
- `name`：字段名，使用 small_snake_case（例如 `region_id`、`vpc_id`）。用于使用统一标准转换为私有（例如 `regionId`、`vpcId`）或公有（例如 `RegionId`、`VpcId`）结构体及接口名称。
- `orm_name`：资源的 ORM 对象字段名称，需要与 ORM 定义保持一致。用于生成 db 相关的代码，大部分情况下是对 cache 结构体字段的映射，如 `dbItem.RegionID`、`dbItem.VPCID`。
- `type`：Go 类型（如 `int`、`string`），集合字段使用 `set`。
- `of`：（仅当 `type: set` 时）集合元素类型（如 `int`）。生成器运行时将 `type: set` + `of: int` 转换为 `mapset.Set[int]`，并生成 `ToSlice`/`Add`/`Remove` 相关方法。
- `for_validation`：是否作为 `IsValid()` 的校验字段。
- `for_index`：是否作为索引字段（生成 `GetByX`/`GetOrLoadByX` 方法）。
- `for_mutation`：是否生成 setter 方法（`SetX`）。
- `is_extension`：是否为扩展字段；在扩展文件中手动实现。
- `ref`：外键引用配置，用于将 ORM 字段值转换为关联资源的指定字段值。
  - `resource`：引用的资源类型，使用 small_snake_case（如 `region`、`az`）。
  - `lookup_by`：在引用资源中查找目标对象的方式，使用 small_snake_case（如 `lcuuid`、`id`）。
  - `target`：返回对象中要获取的字段名，使用 small_snake_case（如 `id`、`lcuuid`）。
- `comment`：字段注释。

## 3. 其他说明
### 扩展文件
当 `extensions` 不为空时，可在同级目录放置扩展文件：
- `<name>_ext.go`：结构体扩展字段与额外 import。
- `<PublicName>CollectionExt`：集合扩展实现。

生成器会从扩展文件中提取 import 与扩展字段定义，并注入到生成代码中。

### 命名约定
- `name` 与 YAML 文件名保持一致（例如 `pod_node.yaml` 对应 `name: pod_node`）。
- `ref.resource` 使用 small_snake_case（例如 `region`、`az`）。

### 示例
```yaml
name: pod_node
orm_name: PodNode
cache_tool:
  enabled: true
  fields:
  - name: lcuuid
    orm_name: Lcuuid
    type: string
    for_validation: true
  - name: region_id
    orm_name: Region
    type: int
    ref:
      resource: region
      lookup_by: lcuuid
      target: id
```

如需新增资源：
1) 新建 YAML 配置；
2) 运行生成器；
3) 根据需要补充扩展文件。

---

# Cache Diffbase Config 说明

## 1. 配置文件用途
本目录同时用于描述 recorder 的 cache diffbase 代码生成配置。每个 YAML 文件可以同时包含 `cache_tool` 和 `cache_diffbase` 两个模块的配置，生成器读取配置后分别输出 Go 代码到对应目录。

- 生成模板：[server/controller/recorder/generator/cache_diffbase.go.tpl](server/controller/recorder/generator/cache_diffbase.go.tpl)
- 输出目录：`server/controller/recorder/cache/diffbase/`

## 2. 配置字段说明
### 顶层字段
- `name`：资源名称，使用 small_snake_case（例如 `pod_node`、`az`）。
- `orm_name`：资源的 ORM 对象名称，需要与 ORM 定义保持一致。
- `cache_diffbase`：recorder 中的 cache/diffbase 模块配置。

### cache_diffbase 字段
- `enabled`：是否启用该模块的代码生成。
- `fields`：该资源 diffbase 结构体字段列表。
- `extensions`：扩展字段列表（可选）可选 `collection` 或 `struct`。
  - `collection`：集合包含扩展定义 `<PublicName>CollectionExt`，需要在 `<name>_ext.go` 中手动实现。
  - `struct`：结构体包含扩展定义 `<PublicName>Ext`，需要在 `<name>_ext.go` 中手动实现。

### fields 字段项
- `name`：字段名，使用 small_snake_case（例如 `region_lcuuid`、`vpc_id`）。用于使用统一标准转换为公有结构体字段名称。
- `orm_name`：资源的 ORM 对象字段名称，需要与 ORM 定义保持一致。用于生成 db 相关的代码。
- `type`：Go 类型（如 `int`、`string`、`map[string]string`），集合字段使用 `list`。
- `of`：（仅当 `type: list` 时）集合元素类型（如 `string`）。
- `from`：（可选）数据源类型转换，如 `bytes` 表示需要从 `[]byte` 转换。
- `is_large`：是否为大字段，启用后会生成 `ToLoggable()` 方法（日志输出时隐藏）。
- `is_extension`：是否为扩展字段；在扩展文件中手动实现。
- `ref`：外键引用配置，用于将 ORM 字段值转换为关联资源的指定字段值。
  - `resource`：引用的资源类型，使用 small_snake_case（如 `vpc`、`network`）。
  - `lookup_by`：在引用资源中查找目标对象的方式，使用 small_snake_case（如 `id`、`ip`）。
  - `target`：返回对象中要获取的字段名，使用 small_snake_case（如 `lcuuid`、`id`）。
- `comment`：（可选）字段注释。

## 3. 示例
### 基础配置示例
```yaml
name: az
orm_name: AZ

cache_diffbase:
  enabled: true
  fields:
    - name: name
      orm_name: Name
      type: string
    - name: label
      orm_name: Label
      type: string
    - name: region_lcuuid
      orm_name: Region
      type: string
```

### 包含外键引用的配置示例
```yaml
name: vm
orm_name: VM

cache_diffbase:
  enabled: true
  fields:
    - name: name
      orm_name: Name
      type: string
    - name: vpc_lcuuid
      orm_name: VPCID
      type: string
      ref:
        resource: vpc
        lookup_by: id
        target: lcuuid
    - name: host_id
      orm_name: LaunchServer
      type: int
      ref:
        resource: host
        lookup_by: ip
        target: id
```

### 包含集合字段的配置示例
```yaml
name: cen
orm_name: CEN

cache_diffbase:
  enabled: true
  fields:
    - name: name
      orm_name: Name
      type: string
    - name: vpc_lcuuids
      orm_name: VPCIDs
      type: list
      of: string
      ref:
        resource: vpc
        lookup_by: id
        target: lcuuid
```

### 包含扩展的配置示例
```yaml
name: vinterface
orm_name: VInterface

cache_diffbase:
  enabled: true
  fields:
    - name: name
      orm_name: Name
      type: string
    - name: device_lcuuid
      orm_name: DeviceLcuuid
      type: string
      is_extension: true
    - name: network_lcuuid
      orm_name: NetworkID
      type: string
      ref:
        resource: network
        lookup_by: id
        target: lcuuid
  extensions:
    - struct
```

## 4. 其他说明
### 扩展文件
当 `extensions` 包含 `struct` 或存在 `is_extension: true` 的字段时，需要在 `cache/diffbase/` 目录下创建扩展文件：
- `<name>_ext.go`：定义 `<PublicName>Ext` 结构体，并实现 `resetExt(dbItem, tool)` 方法处理扩展字段逻辑。

### 命名约定
- `name` 使用 small_snake_case（与 cache_tool 的 fields.name 风格一致）。
- `ref.resource` 使用 small_snake_case（如 `vpc`、`network`、`pod_ingress`）。
