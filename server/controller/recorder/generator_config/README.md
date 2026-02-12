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
- `type`：Go 类型（如 `int`、`string`）。
- `for_validation`：是否作为 `IsValid()` 的校验字段。
- `for_index`：是否作为索引字段（生成 `GetByX`/`GetOrLoadByX` 方法）。
- `for_mutation`：是否生成 setter 方法（`SetX`）。
- `is_extension`：是否为扩展字段；在扩展文件中手动实现。
- `is_collection`：是否为集合字段；启用后会生成 `ToSlice`/`Add`/`Remove` 相关方法。
- `ref`：外键引用配置，用于将 ORM 字段值转换为关联资源的指定字段值。
  - `resource`：引用的资源类型，对应 `tool` 中的获取方法（如 `Region` 对应 `tool.Region()`）。
  - `lookup_method`：在引用资源中查找目标对象的方法名（如 `GetByLcuuid`）。
  - `target_field`：返回对象中要获取的字段名（如 `Id`）。
- `comment`：字段注释。

## 3. 其他说明
### 扩展文件
当 `extensions` 不为空时，可在同级目录放置扩展文件：
- `<name>_ext.go`：结构体扩展字段与额外 import。
- `<PublicName>CollectionExt`：集合扩展实现。

生成器会从扩展文件中提取 import 与扩展字段定义，并注入到生成代码中。

### 命名约定
- `name` 与 YAML 文件名保持一致（例如 `pod_node.yaml` 对应 `name: pod_node`）。
- `ref.resource` 与资源公开名称一致（例如 `Region`、`Az`）。

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
      resource: Region
      lookup_method: GetByLcuuid
      target_field: Id
```

如需新增资源：
1) 新建 YAML 配置；
2) 运行生成器；
3) 根据需要补充扩展文件。
