-- ============================================================================
-- 数据库升级脚本
-- 版本：7.1.0.31
-- 描述：为 sub_domain 表添加 deleted_at 字段，支持软删除功能
-- ============================================================================

-- 通用检查存储过程定义
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

-- 具体变更操作存储过程定义
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

-- ============================================================================
-- 执行变更操作
-- ============================================================================

-- 为 sub_domain 表添加 deleted_at 字段
CALL AddColumnIfNotExists('sub_domain', 'deleted_at', 'DATETIME DEFAULT NULL', 'updated_at');

-- ============================================================================
-- 清理和版本更新
-- ============================================================================

-- 清理临时存储过程
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
DROP PROCEDURE IF EXISTS ColumnExists;

-- 更新数据库版本
UPDATE db_version SET version='7.1.0.31';

-- ============================================================================
-- 变更完成
-- ============================================================================
