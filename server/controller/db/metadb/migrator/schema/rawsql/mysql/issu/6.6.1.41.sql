DROP PROCEDURE IF EXISTS RenameColumnIfExists;

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

-- Rename alias to alias_bak for vm table
CALL RenameColumnIfExists('vm', 'alias', 'alias_bak', 'CHAR(64) DEFAULT ""');

-- Rename alias to alias_bak for pod_namespace table
CALL RenameColumnIfExists('pod_namespace', 'alias', 'alias_bak', 'CHAR(64) DEFAULT ""');

DROP PROCEDURE RenameColumnIfExists;

UPDATE vm SET custom_cloud_tags = '{}' WHERE custom_cloud_tags IS NULL;
UPDATE pod_namespace SET custom_cloud_tags = '{}' WHERE custom_cloud_tags IS NULL;

UPDATE db_version SET version='6.6.1.41';
