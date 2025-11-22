# rawsql 文件组织规范

本目录存储各类型数据库的原始SQL文件，包括数据库初始化文件和版本升级文件。以下是基于MySQL目录结构的文件组织规范。

## 目录结构

```
rawsql/
├── mysql/                          # MySQL数据库SQL文件
│   ├── ddl_create_table.sql        # 数据表创建DDL语句
│   ├── ddl_create_table_db_version.sql  # 版本表创建语句
│   ├── dml_insert.sql              # 基础数据插入语句
│   ├── default_db_dml_insert.sql   # 默认数据库专用插入语句
│   ├── sqlfmt.go                   # SQL格式化工具
│   ├── issu/                       # 版本升级文件目录
│   │   ├── 6.1.1.0.sql
│   │   ├── 6.1.1.1.sql
│   │   └── ...
│   └── issu_tmpl/                  # 升级模板文件
│       ├── ddl.sql
│       ├── distinguish_db.sql
│       ├── dml.sql
│       └── procedure.sql
├── postgresql/                     # PostgreSQL数据库SQL文件（同 MySQL）
└── README.md                       # 本文档
```

## 文件命名规范

### 1. 数据库初始化文件

初始化文件按照前缀和功能进行分类，系统会按照特定顺序执行这些文件：

#### DDL文件（数据定义语言）
以 `ddl_` 开头的文件，按执行优先级分为：

**高优先级（最先执行）：**
- `ddl_*create_table*.sql` - 包含create_table关键字的文件
- 例如：`ddl_create_table.sql`、`ddl_create_table_db_version.sql`

**中等优先级：**
- `ddl_*.sql` - 其他DDL操作文件
- 例如：`ddl_create_index.sql`、`ddl_create_view.sql`

**低优先级（最后执行的DDL）：**
- `ddl_*create_trigger*.sql` - 包含create_trigger关键字的文件
- 例如：`ddl_create_trigger.sql`

#### DML文件（数据操作语言）
以 `dml_` 开头的文件，在所有DDL文件执行完成后执行：

- `dml_insert.sql` - 基础数据插入
- `dml_update.sql` - 数据更新脚本
- 其他 `dml_*.sql` 文件按字母顺序执行

#### 默认数据库专用文件
以 `default_db_` 开头的文件，仅在默认数据库中执行：

- `default_db_ddl_*.sql` - 默认数据库的DDL操作
- `default_db_dml_*.sql` - 默认数据库的DML操作
- 执行顺序遵循去掉前缀后的同样规律

### 2. 版本升级文件（issu目录）

版本升级文件采用语义化版本号命名，格式为：`{major}.{minor}.{internal}.{build}.sql`

**命名规则：**
- `major`: 大版本号（重大功能更新）
- `minor`: 次版本号（功能增加）
- `internal`: 内部版本号
- `build`: 构建版本号

**示例：**
```
6.1.1.0.sql     # 版本6.1.1的第0个构建版本
6.1.1.1.sql     # 版本6.1.1的第1个构建版本
6.2.1.0.sql     # 版本6.2.1的第0个构建版本
```

### 3. 升级模板文件（issu_tmpl目录）

| 文件名 | 作用 | 说明 |
|--------|------|------|
| `ddl.sql` | DDL操作模板 | CREATE/DROP/ALTER操作的标准模板 |
| `distinguish_db.sql` | 数据库区分模板 | 区分默认数据库和非默认数据库的操作模板 |
| `dml.sql` | DML事务模板 | INSERT/UPDATE/DELETE事务操作模板 |
| `procedure.sql` | 存储过程模板 | 存储过程定义模板 |

## 文件执行顺序

系统会自动按照以下顺序执行SQL文件：

### 普通数据库初始化顺序
1. **DDL创建表文件**（优先级0）：`ddl_*create_table*.sql`
2. **其他DDL文件**（优先级1）：`ddl_*.sql`（除创建表和触发器外）
3. **DDL创建触发器文件**（优先级2）：`ddl_*create_trigger*.sql`
4. **DML文件**（优先级3）：`dml_*.sql`
5. **其他文件**（优先级4）：不符合上述规律的`.sql`文件

### 默认数据库专用文件执行顺序
当处理默认数据库时，系统会：
1. 只选择以`default_db_`开头的文件
2. 去掉`default_db_`前缀后按照相同规律排序
3. 按优先级执行

### 同优先级文件排序
同一优先级内的文件按文件名字母顺序执行。

### 版本升级文件执行
`issu/`目录中的文件按版本号顺序执行：
- 文件名格式：`{major}.{minor}.{internal}.{build}.sql`
- 按版本号数值大小排序，从小到大执行

## SQL文件内容规范

### 1. 初始化文件内容要求

#### ddl_create_table.sql
```sql
-- 建议按功能模块组织表结构，如：
-- ============================================================================
-- SECTION HIERARCHY
-- System
--   Controllers
--   Agents
--   Analyzers
-- Assets
--   Clouds
--   Network Services
-- ============================================================================

-- System - Controllers
CREATE TABLE IF NOT EXISTS controller (
    id                  INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    -- 字段定义...
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;
TRUNCATE TABLE controller;
```

#### dml_insert.sql
```sql
-- 使用UUID生成器确保数据唯一性
set @lcuuid = (select uuid());
INSERT INTO sys_configuration (`param_name`, `value`, `comments`, `lcuuid`) 
VALUES ('cloud_sync_timer', '60', 'unit: s', @lcuuid);
```

### 2. 升级文件内容要求

#### 版本升级文件
```sql
/*RENAME TABLE*/
RENAME TABLE old_table_name TO new_table_name;

/*CREATE TABLE*/
CREATE TABLE IF NOT EXISTS new_table (
    -- 字段定义...
);

/*ALTER TABLE*/
ALTER TABLE existing_table ADD COLUMN new_column VARCHAR(256);

/*INSERT DATA*/
INSERT INTO table_name VALUES (...);

-- 必须更新版本号
UPDATE db_version SET version='6.1.1.0';
```

### 3. 模板文件使用说明

#### ddl.sql 模板
- 用于不需要事务的DDL操作
- 每个操作应该在单独的升级文件中执行
- 必须更新db_version表

#### distinguish_db.sql 模板
- 用于需要区分默认数据库和非默认数据库的操作
- 使用存储过程处理不同数据库的差异化逻辑

#### dml.sql 模板
- 用于需要事务保护的DML操作
- 确保数据一致性

## 文件命名建议

### 初始化文件命名
根据文件执行优先级，建议按以下规律命名：

**DDL文件（按执行顺序）：**
- `ddl_create_table.sql` - 主表创建（最高优先级）
- `ddl_create_table_*.sql` - 其他表创建
- `ddl_create_index.sql` - 索引创建
- `ddl_create_view.sql` - 视图创建  
- `ddl_create_trigger.sql` - 触发器创建（DDL最低优先级）

**DML文件：**
- `dml_insert.sql` - 基础数据插入
- `dml_insert_*.sql` - 特定模块数据插入

**默认数据库专用文件：**
- `default_db_ddl_*.sql` - 默认数据库的DDL操作
- `default_db_dml_*.sql` - 默认数据库的DML操作

### 文件名中的关键字
系统会根据文件名中的关键字来确定执行顺序：
- 包含`create_table`的文件会最先执行
- 包含`create_trigger`的文件会在其他DDL文件之后执行
- 其他文件按字母顺序在对应优先级组内执行

## 文件添加指南

### 1. 添加新的初始化数据

**场景：** 需要为新功能添加基础配置数据

**步骤：**
1. 确定数据类型（通用数据 vs 默认数据库专用数据）
2. 在相应文件中添加INSERT语句：
   - 通用数据 → `dml_insert.sql`
   - 默认数据库专用 → `default_db_dml_insert.sql`

### 2. 添加新的数据表

**场景：** 新功能需要创建数据表

**步骤：**
1. 创建或修改包含`create_table`关键字的DDL文件（如`ddl_create_table.sql`）
2. 按功能模块归类，添加适当的注释分区
3. 添加TRUNCATE语句确保初始化时表为空
4. 如果需要创建索引或视图，放在其他`ddl_*.sql`文件中
5. 如果需要创建触发器，放在包含`create_trigger`关键字的文件中

### 3. 添加版本升级脚本

**场景：** 发布新版本需要数据库升级

**步骤：**
1. 确定版本号（如：6.3.1.25）
2. 在`issu/`目录创建文件：`6.3.1.25.sql`
3. 根据操作类型选择合适的模板：
   - DDL操作 → 参考`ddl.sql`
   - 数据库差异化操作 → 参考`distinguish_db.sql`
   - DML操作 → 参考`dml.sql`
4. 在文件末尾更新版本号：`UPDATE db_version SET version='6.3.1.25';`

### 4. 支持新数据库类型

**场景：** 需要支持PostgreSQL或其他数据库

**步骤：**
1. 创建新的数据库目录（如：`postgresql/`）
2. 复制MySQL目录结构
3. 转换SQL语法适配目标数据库
4. 更新migrator代码以支持新数据库类型

## 注意事项

### 1. 版本管理
- 每个升级文件只处理一个版本的变更
- 版本号必须与代码中的期望版本一致
- 升级文件按版本号顺序执行

### 2. SQL兼容性
- 使用IF NOT EXISTS确保重复执行安全
- DDL操作不使用事务（不同数据库行为不一致）
- 使用标准SQL语法提高兼容性

### 3. 数据安全
- 重要操作前备份数据
- 使用事务保护数据修改操作
- 测试升级脚本的幂等性

### 4. 代码同步
- SQL文件变更后同步更新Go代码中的版本常量
- 确保migrator代码能正确读取和执行SQL文件

## 扩展其他数据库

当需要支持新的数据库类型时，按以下步骤操作：

1. **创建数据库目录**
   ```
   rawsql/
   ├── postgresql/
   │   ├── ddl_create_table.sql
   │   ├── dml_insert.sql
   │   └── issu/
   ```

2. **转换SQL语法**
   - 数据类型映射（如 postgresql ：INTEGER → SERIAL）
   - 语法差异处理（如 postgresql ：AUTO_INCREMENT → SERIAL）
   - 函数调用适配（如 postgresql ：uuid() → gen_random_uuid()）

3. **更新配置和代码**
   - 在配置中添加新数据库支持
   - 更新migrator读取逻辑
   - 添加数据库特定的SQL格式化工具

通过遵循以上规范，可以确保SQL文件的有序管理和版本升级的顺利进行。
