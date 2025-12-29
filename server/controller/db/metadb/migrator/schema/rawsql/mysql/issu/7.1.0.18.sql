-- ColumnExists function
DROP PROCEDURE IF EXISTS ColumnExists;

CREATE PROCEDURE ColumnExists(
    IN  p_table_name VARCHAR(255),
    IN  p_col_name   VARCHAR(255),
    OUT p_exists     TINYINT(1)
)
BEGIN
    SELECT COUNT(*) > 0
    INTO p_exists
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = p_table_name
      AND COLUMN_NAME  = p_col_name;
END;

-- AddColumnIfNotExists procedure
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
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;
CALL AddColumnIfNotExists('custom_service', 'pod_namespace_ids', 'TEXT COMMENT "separated by ,"', 'match_type');
CALL AddColumnIfNotExists('custom_service', 'pod_cluster_ids', 'TEXT COMMENT "separated by ,"', 'match_type');
CALL AddColumnIfNotExists('custom_service', 'epc_ids', 'TEXT COMMENT "separated by ,"', 'match_type');

-- ChangeColumnIfExists procedure
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;

CREATE PROCEDURE ChangeColumnIfExists(
    IN tableName VARCHAR(255),
    IN oldColName VARCHAR(255),
    IN newColName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    CALL ColumnExists(tableName, oldColName, @exists);
    IF @exists THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE ', oldColName, ' ', newColName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL ChangeColumnIfExists('custom_service', 'epc_id', 'epc_id_bak', 'INTEGER DEFAULT 0');
CALL ChangeColumnIfExists('custom_service', 'pod_cluster_id', 'pod_cluster_id_bak', 'INTEGER DEFAULT 0');
CALL ChangeColumnIfExists('custom_service', 'pod_namespace_id', 'pod_namespace_id_bak', 'INTEGER DEFAULT 0');
CALL ChangeColumnIfExists('custom_service', 'resource', 'resources', 'TEXT COMMENT "separated by ,"');

-- MigrateData
DROP PROCEDURE IF EXISTS MigrateData;

CREATE PROCEDURE MigrateData(
    IN tableName VARCHAR(255),
    IN sourceColName VARCHAR(255),
    IN targetColName VARCHAR(255)
)
BEGIN
    CALL ColumnExists(tableName, sourceColName, @source_exists);
    CALL ColumnExists(tableName, targetColName, @target_exists);
    IF @source_exists AND @target_exists THEN
        SET @sql = CONCAT('UPDATE ', tableName, ' SET ', targetColName, ' = ', sourceColName, ' WHERE ', sourceColName, ' > 0 AND (', targetColName, ' IS NULL OR ', targetColName, ' = "")');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
        SET @sql = CONCAT('UPDATE ', tableName, ' SET ', targetColName, ' = "" WHERE ', sourceColName, ' = 0 AND (', targetColName, ' IS NULL OR ', targetColName, ' = "")');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;
CALL MigrateData('custom_service', 'epc_id_bak', 'epc_ids');
CALL MigrateData('custom_service', 'pod_cluster_id_bak', 'pod_cluster_ids');
CALL MigrateData('custom_service', 'pod_namespace_id_bak', 'pod_namespace_ids');

-- Cleanup
DROP PROCEDURE IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;
DROP PROCEDURE IF EXISTS MigrateData;

-- Update DB version
UPDATE db_version SET version='7.1.0.18';
