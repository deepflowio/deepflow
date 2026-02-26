# 数据库升级完整工作流程指南

基于数据库结构变更实践，总结出以下标准化数据库升级工作流程，适用于各类数据库变更场景：

## 1. 初始化文件修改
**目标文件**：根据初始需求描述确定，可能包括：
- `db/metadb/migrator/schema/rawsql/{database}/ddl_create_table.sql` - 主表创建文件
- `db/metadb/migrator/schema/rawsql/{database}/ddl_create_index.sql` - 索引创建文件
- `db/metadb/migrator/schema/rawsql/{database}/ddl_create_view.sql` - 视图创建文件
- `db/metadb/migrator/schema/rawsql/{database}/ddl_create_trigger.sql` - 触发器创建文件
- `db/metadb/migrator/schema/rawsql/{database}/dml_insert.sql` - 基础数据插入文件
- `db/metadb/migrator/schema/rawsql/{database}/default_db_*.sql` - 默认数据库专用文件
- 其他相关的初始化 SQL 文件

**操作要点**：
- 修改对应文件中的定义，确保与预期最终状态一致
- 同步修改所有支持的数据库类型（mysql/postgresql 等）
- 遵循 README.md 中的文件命名和执行顺序规范

## 2. ISSU 升级脚本实现
**目标文件**：`db/metadb/migrator/schema/rawsql/{database}/issu/{version}.sql`

### 版本号确定规则
- 查看现有最高版本号：`ls issu/ | sort -V | tail -1`
- 按规律递增 build 号：`{major}.{minor}.{internal}.{build+1}.sql`

### 通用存储过程模板
```sql
-- 通用检查存储过程
-- ColumnExists procedure
DROP PROCEDURE IF EXISTS ColumnExists;
CREATE PROCEDURE ColumnExists(
    IN  p_table_name VARCHAR(255),
    IN  p_col_name   VARCHAR(255),
    OUT p_exists     TINYINT(1)
)
BEGIN
    SELECT COUNT(*) > 0 INTO p_exists
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = p_table_name
      AND COLUMN_NAME = p_col_name;
END;

-- TableExists procedure
DROP PROCEDURE IF EXISTS TableExists;
CREATE PROCEDURE TableExists(
    IN  p_table_name VARCHAR(255),
    OUT p_exists     TINYINT(1)
)
BEGIN
    SELECT COUNT(*) > 0 INTO p_exists
    FROM information_schema.tables
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = p_table_name;
END;

-- IndexExists procedure
DROP PROCEDURE IF EXISTS IndexExists;
CREATE PROCEDURE IndexExists(
    IN  p_table_name VARCHAR(255),
    IN  p_index_name VARCHAR(255),
    OUT p_exists     TINYINT(1)
)
BEGIN
    SELECT COUNT(*) > 0 INTO p_exists
    FROM information_schema.statistics
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = p_table_name
      AND INDEX_NAME = p_index_name;
END;
```

### 具体操作存储过程模板

#### 表结构变更
```sql
-- 字段重命名/类型变更
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;
CREATE PROCEDURE ChangeColumnIfExists(
    IN tableName VARCHAR(255),
    IN oldColName VARCHAR(255),
    IN newColName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    CALL ColumnExists(tableName, oldColName, @old_exists);
    CALL ColumnExists(tableName, newColName, @new_exists);
    IF @old_exists AND NOT @new_exists THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE COLUMN ', oldColName, ' ', newColName, ' ', colType);
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;

-- 新增字段
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
CREATE PROCEDURE AddColumnIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    CALL ColumnExists(tableName, colName, @exists);
    IF NOT @exists THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, 
                         IF(afterCol = '', '', CONCAT(' AFTER ', afterCol)));
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;

-- 删除字段
DROP PROCEDURE IF EXISTS DropColumnIfExists;
CREATE PROCEDURE DropColumnIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255)
)
BEGIN
    CALL ColumnExists(tableName, colName, @exists);
    IF @exists THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' DROP COLUMN ', colName);
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;
```

#### 表管理
```sql
-- 创建表
DROP PROCEDURE IF EXISTS CreateTableIfNotExists;
CREATE PROCEDURE CreateTableIfNotExists(
    IN tableName VARCHAR(255),
    IN tableSQL TEXT
)
BEGIN
    CALL TableExists(tableName, @exists);
    IF NOT @exists THEN
        SET @sql = tableSQL;
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;

-- 删除表
DROP PROCEDURE IF EXISTS DropTableIfExists;
CREATE PROCEDURE DropTableIfExists(
    IN tableName VARCHAR(255)
)
BEGIN
    CALL TableExists(tableName, @exists);
    IF @exists THEN
        SET @sql = CONCAT('DROP TABLE ', tableName);
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;
```

#### 索引管理
```sql
-- 创建索引
DROP PROCEDURE IF EXISTS CreateIndexIfNotExists;
CREATE PROCEDURE CreateIndexIfNotExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255),
    IN indexSQL TEXT
)
BEGIN
    CALL IndexExists(tableName, indexName, @exists);
    IF NOT @exists THEN
        SET @sql = indexSQL;
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;

-- 删除索引
DROP PROCEDURE IF EXISTS DropIndexIfExists;
CREATE PROCEDURE DropIndexIfExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255)
)
BEGIN
    CALL IndexExists(tableName, indexName, @exists);
    IF @exists THEN
        SET @sql = CONCAT('DROP INDEX ', indexName, ' ON ', tableName);
        PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
    END IF;
END;
```

#### 数据操作
```sql
-- 数据迁移/更新（事务保护）
-- 注意：对于DML操作，建议使用事务保护
START TRANSACTION;
-- 执行数据操作
-- UPDATE/INSERT/DELETE statements
COMMIT;
```

### 关键原则
- **幂等性**：可重复执行，结果一致
- **安全性**：检查前置条件，避免错误操作
- **清理性**：执行完毕后清理临时存储过程
- **事务性**：DML操作使用事务保护

## 3. 版本控制校验变量修改
**目标文件**：`db/metadb/migrator/schema/const.go`
- 修改 `DB_VERSION_EXPECTED` 常量为新版本号
- 确保与 ISSU 脚本中的版本号完全一致

## 4. ORM 模型同步修改

### 外部模块 ORM 定义
**目标文件**：通常在 `server/agent_config/db.go` 或类似外部模块
- 修改对应结构体的字段定义
- 更新 GORM 标签：`column`、`type`、`json` 等
- 确保字段类型与数据库 DDL 一致
- 新增/删除表时，对应增删结构体定义

### 查找 ORM 文件的方法
1. 通过 import 语句查找：`grep -r "import.*agent_config"`
2. 通过结构体名称查找：`grep -r "MetadbXxxXxx"`
3. 通过语义搜索：`semantic_search "struct ORM model"`

## 5. ORM 相关业务逻辑修改

### 自动化查找受影响文件
```bash
# 查找使用旧字段名/表名的文件
grep -r "OldName" --include="*.go"
# 查找使用结构体的文件
grep -r "StructName" --include="*.go"
```

### 需要更新的层次
1. **HTTP Model 层**：请求/响应结构体定义
2. **Service 层**：业务逻辑中的字段/表使用
3. **Repository 层**：数据访问层的 SQL 语句
4. **测试文件**：模拟数据和断言
5. **其他引用**：类型转换、序列化等

### 更新原则
- 保持 API 兼容性（必要时保留向后兼容）
- 更新所有硬编码的名称引用
- 确保测试数据与新结构一致

## 6. 模板文件更新（可选）
**目标文件**：`db/metadb/migrator/schema/rawsql/{database}/issu_tmpl/ddl.sql`
- 将本次实践的存储过程模式加入模板
- 为后续开发者提供参考

## 7. 验证清单
- [ ] 编译通过，无语法错误
- [ ] 单元测试通过
- [ ] 数据库迁移脚本可重复执行
- [ ] API 接口兼容性验证
- [ ] 所有硬编码名称已更新
- [ ] 数据完整性验证

## 常见数据库变更类型

### A. 字段变更

### A. 字段变更

#### 1. 字段重命名 + 类型变更
```sql
-- 示例：user_id (INTEGER) → user (VARCHAR)
CALL ChangeColumnIfExists('table_name', 'user_id', 'user', 'VARCHAR(256) NOT NULL');
```

#### 2. 新增字段
```sql
-- 示例：添加 created_by 字段
CALL AddColumnIfNotExists('table_name', 'created_by', 'VARCHAR(256) DEFAULT NULL', 'last_column');
```

#### 3. 删除字段
```sql
-- 示例：删除废弃的 old_field 字段
CALL DropColumnIfExists('table_name', 'old_field');
```

#### 4. 字段类型变更（同名）
```sql
-- 示例：扩大字段长度
CALL ChangeColumnIfExists('table_name', 'description', 'description', 'TEXT');
```

### B. 表管理

#### 1. 新建表
```sql
-- 示例：创建新表
SET @create_sql = 'CREATE TABLE IF NOT EXISTS new_table (
    id INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8';
CALL CreateTableIfNotExists('new_table', @create_sql);
```

#### 2. 删除表
```sql
-- 示例：删除废弃表
CALL DropTableIfExists('old_table');
```

#### 3. 表重命名
```sql
-- 直接使用 RENAME TABLE（MySQL原生支持幂等）
RENAME TABLE old_table TO new_table;
```

### C. 索引管理

#### 1. 创建索引
```sql
-- 示例：创建普通索引
SET @index_sql = 'CREATE INDEX idx_user_name ON user_table (name)';
CALL CreateIndexIfNotExists('user_table', 'idx_user_name', @index_sql);

-- 示例：创建唯一索引
SET @unique_sql = 'CREATE UNIQUE INDEX uk_user_email ON user_table (email)';
CALL CreateIndexIfNotExists('user_table', 'uk_user_email', @unique_sql);
```

#### 2. 删除索引
```sql
-- 示例：删除索引
CALL DropIndexIfExists('user_table', 'idx_old_field');
```

### D. 数据迁移

#### 1. 数据更新
```sql
-- 示例：批量更新数据（使用事务保护）
START TRANSACTION;
UPDATE table_name SET status = 'active' WHERE status IS NULL;
COMMIT;
```

#### 2. 数据迁移（跨表）
```sql
-- 示例：从旧表迁移数据到新表
START TRANSACTION;
INSERT INTO new_table (name, email, created_at)
SELECT old_name, old_email, old_created_time FROM old_table
WHERE id NOT IN (SELECT old_id FROM new_table WHERE old_id IS NOT NULL);
COMMIT;
```

#### 3. 数据清理
```sql
-- 示例：清理过期数据（使用事务保护）
START TRANSACTION;
DELETE FROM log_table WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
COMMIT;
```

### E. 约束管理

#### 1. 外键约束
```sql
-- 添加外键约束（需要先检查约束是否存在）
SET @constraint_name = 'fk_user_department';
SET @add_fk_sql = CONCAT('ALTER TABLE user_table ADD CONSTRAINT ', @constraint_name, 
                        ' FOREIGN KEY (dept_id) REFERENCES department(id)');

-- 检查约束是否存在的存储过程
DROP PROCEDURE IF EXISTS ConstraintExists;
CREATE PROCEDURE ConstraintExists(
    IN p_table_name VARCHAR(255),
    IN p_constraint_name VARCHAR(255),
    OUT p_exists TINYINT(1)
)
BEGIN
    SELECT COUNT(*) > 0 INTO p_exists
    FROM information_schema.table_constraints
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = p_table_name
      AND CONSTRAINT_NAME = p_constraint_name;
END;

CALL ConstraintExists('user_table', @constraint_name, @exists);
IF NOT @exists THEN
    PREPARE stmt FROM @add_fk_sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
END IF;
DROP PROCEDURE IF EXISTS ConstraintExists;
```

### F. 视图和存储过程

#### 1. 创建/更新视图
```sql
-- 视图创建（CREATE OR REPLACE 天然幂等）
CREATE OR REPLACE VIEW user_summary AS
SELECT u.id, u.name, d.name as dept_name
FROM user_table u LEFT JOIN department d ON u.dept_id = d.id;
```

#### 2. 存储过程管理
```sql
-- 存储过程更新（DROP IF EXISTS + CREATE 实现幂等）
DROP PROCEDURE IF EXISTS GetUsersByDept;
CREATE PROCEDURE GetUsersByDept(IN dept_id INT)
BEGIN
    SELECT * FROM user_table WHERE dept_id = dept_id;
END;
```

## 升级脚本最终模板

```sql
-- ============================================================================
-- 数据库升级脚本模板
-- 版本：{version}
-- 描述：{change_description}
-- ============================================================================

-- 通用检查存储过程定义
{include_common_procedures}

-- 具体变更操作存储过程定义
{include_specific_procedures}

-- ============================================================================
-- 执行变更操作
-- ============================================================================

-- 表结构变更
{table_structure_changes}

-- 数据变更（使用事务保护）
{data_migrations}

-- 索引变更
{index_changes}

-- 约束变更
{constraint_changes}

-- 视图/存储过程变更
{view_procedure_changes}

-- ============================================================================
-- 清理和版本更新
-- ============================================================================

-- 清理临时存储过程
{cleanup_procedures}

-- 更新数据库版本
UPDATE db_version SET version='{version}';

-- ============================================================================
-- 变更完成
-- ============================================================================
```

## 补充建议

### 工作流程自动化
1. **变更分析工具**：自动分析变更类型并生成对应的 ISSU 脚本模板
2. **依赖分析工具**：自动查找所有相关的代码位置
3. **测试数据生成**：根据新结构自动更新测试数据

### 风险控制策略
1. **分阶段发布**：大型变更分多个版本逐步实施
2. **数据备份**：重要变更前自动备份相关数据
3. **回滚机制**：为每个变更准备对应的回滚脚本
4. **监控验证**：变更后自动验证数据完整性

### 文档和沟通
1. **变更影响评估**：评估对现有功能和性能的影响
2. **API 兼容性说明**：明确向前兼容性策略
3. **运维协调**：与运维团队协调发布窗口和监控要求

---

此指南涵盖了数据库升级的所有常见场景，确保了升级过程的完整性、安全性和可维护性。