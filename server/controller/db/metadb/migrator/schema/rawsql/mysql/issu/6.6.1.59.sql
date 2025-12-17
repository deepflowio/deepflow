-- ColumnExists function
DROP FUNCTION IF EXISTS ColumnExists;

CREATE FUNCTION ColumnExists(
    tableName VARCHAR(255),
    colName VARCHAR(255)
)
RETURNS TINYINT(1)
DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND COLUMN_NAME = colName;

    RETURN column_count > 0;
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
    IF NOT ColumnExists(tableName, colName) THEN
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
    IF ColumnExists(tableName, oldColName) THEN
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
    IF ColumnExists(tableName, sourceColName) AND ColumnExists(tableName, targetColName) THEN
        SET @sql = CONCAT('UPDATE ', tableName, ' SET ', targetColName, ' = ', sourceColName, ' WHERE ', sourceColName, ' > 0');
        SET @sql = CONCAT('UPDATE ', tableName, ' SET ', targetColName, ' = "" WHERE ', sourceColName, ' = 0');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;
CALL MigrateData('custom_service', 'epc_id_bak', 'epc_ids');
CALL MigrateData('custom_service', 'pod_cluster_id_bak', 'pod_cluster_ids');
CALL MigrateData('custom_service', 'pod_namespace_id_bak', 'pod_namespace_ids');

-- Cleanup
DROP FUNCTION IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;
DROP PROCEDURE IF EXISTS MigrateData;

-- Update DB version
UPDATE db_version SET version='6.6.1.59';
