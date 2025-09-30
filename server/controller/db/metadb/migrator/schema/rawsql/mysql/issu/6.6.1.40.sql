DROP PROCEDURE IF EXISTS RenameColumnIfExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

-- Procedure to rename column if it exists
CREATE PROCEDURE RenameColumnIfExists(
    IN tableName VARCHAR(255),
    IN oldColName VARCHAR(255),
    IN newColName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;
    DECLARE new_column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = oldColName;

    SELECT COUNT(*)
    INTO new_column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = newColName;

    IF column_count > 0 AND new_column_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE COLUMN ', oldColName, ' ', newColName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

-- Procedure to add column if it doesn't exist
CREATE PROCEDURE AddColumnIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    IF column_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

-- Rename cloud_tags to learned_cloud_tags for vm table
CALL RenameColumnIfExists('vm', 'cloud_tags', 'learned_cloud_tags', 'TEXT COMMENT "separated by ,"');

-- Add custom_cloud_tags column to vm table
CALL AddColumnIfNotExists('vm', 'custom_cloud_tags', 'TEXT COMMENT "separated by ,"', 'learned_cloud_tags');

-- Rename cloud_tags to learned_cloud_tags for pod_namespace table
CALL RenameColumnIfExists('pod_namespace', 'cloud_tags', 'learned_cloud_tags', 'TEXT COMMENT "separated by ,"');

-- Add custom_cloud_tags column to pod_namespace table
CALL AddColumnIfNotExists('pod_namespace', 'custom_cloud_tags', 'TEXT COMMENT "separated by ,"', 'learned_cloud_tags');

DROP PROCEDURE RenameColumnIfExists;
DROP PROCEDURE AddColumnIfNotExists;

UPDATE db_version SET version='6.6.1.40';
