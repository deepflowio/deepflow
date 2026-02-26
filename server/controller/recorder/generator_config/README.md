# Cache Tool Config 说明

## 1. 配置文件用途
本目录用于描述 recorder 的 cache tool 代码生成配置。每个 YAML 文件对应一个资源类型，生成器读取配置后输出 Go 代码到 [server/controller/recorder/cache/tool](server/controller/recorder/cache/tool)。

- 生成器入口：[server/controller/recorder/generator/generator.go](server/controller/recorder/generator/generator.go)
- 生成模板：[server/controller/recorder/cache/tool/gen.go.tpl](server/controller/recorder/cache/tool/gen.go.tpl)

## 2. 配置字段说明
### 顶层字段
- `name`：资源名称，使用 small_snake_case（例如 `pod_node`）。用于生成文件名与资源类型标识。
- `public_name`：资源公开名称，使用 PascalCase（例如 `PodNode`）。用于生成公有结构体与方法名称。
- `cache_tool`：cache tool 配置块。

### cache_tool 字段
- `enabled`：是否启用该资源的代码生成。
- `fields`：资源字段列表。
- `key_fields`：索引字段列表（可选）。用于生成 `GetByX`/`GetOrLoadByX` 这类方法。
- `has_extension`：是否支持结构体扩展（对应 `<name>_ext.go`）。
- `collection_extension`：是否支持集合扩展（对应 `<PublicName>CollectionExt`）。
- `has_mapset`：是否启用 `mapset` 支持（用于 plural 字段）。
- `has_custom`：生成器运行时填充，表示是否存在 `is_custom: true` 字段，通常不在配置中手动设置。

### fields 字段项
- `name`：字段名，使用 lowerCamelCase（例如 `regionID`）。用于生成私有结构体字段名。
- `public_name`：字段的公开方法名，使用 PascalCase（例如 `RegionID`）。用于生成公有结构体字段名与方法名。
- `type`：Go 类型（如 `int`、`string`）。
- `is_validation_field`：是否作为 `IsValid()` 的校验字段。
- `ref`：引用的资源类型（如 `Region`、`AZ`），会生成从工具中取 ID 的逻辑。
- `db_field_name`：数据库字段名（若与 `public_name` 不一致时使用）。
- `has_setter`：是否生成 setter 方法（`SetX`）。
- `has_custom`：历史兼容字段，通常不建议使用。
- `is_custom`：是否为自定义字段；自定义字段不会走默认 `reset` 赋值逻辑。
- `is_plural`：是否为集合字段；启用后会生成 `ToSlice`/`Add`/`Remove` 相关方法，并需要 `has_mapset`。
- `comment`：字段注释。

### key_fields 字段项
- `name`：索引字段名。
- `public_name`：索引字段公开名称。
- `type`：Go 类型。

## 3. 其他说明
### 扩展文件
当 `has_extension: true` 或 `collection_extension: true` 时，可在同级目录放置扩展文件：
- `<name>_ext.go`：结构体扩展字段与额外 import。
- `<PublicName>CollectionExt`：集合扩展实现。

生成器会从扩展文件中提取 import 与扩展字段定义，并注入到生成代码中。

### 命名约定
- `name` 与 YAML 文件名保持一致（例如 `pod_node.yaml` 对应 `name: pod_node`）。
- `public_name` 使用 UpperCamelCase。
- `ref` 与资源公开名称一致（例如 `Region`、`AZ`）。

### 示例
```yaml
name: pod_node
public_name: PodNode
cache_tool:
  enabled: true
  fields:
  - name: lcuuid
    public_name: Lcuuid
    type: string
    is_validation_field: true
  - name: regionID
    public_name: RegionID
    type: int
    ref: Region
    db_field_name: Region
```

如需新增资源：
1) 新建 YAML 配置；
2) 运行生成器；
3) 根据需要补充扩展文件。
