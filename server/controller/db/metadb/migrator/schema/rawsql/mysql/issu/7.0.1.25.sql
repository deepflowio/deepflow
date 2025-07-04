DROP PROCEDURE IF EXISTS ModifyColumnIfExists;

CREATE PROCEDURE ModifyColumnIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    IF column_count > 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' MODIFY COLUMN ', colName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL ModifyColumnIfExists('config_map', 'data', 'MEDIUMTEXT COMMENT "yaml"');
CALL ModifyColumnIfExists('pod_service', 'metadata', 'MEDIUMTEXT COMMENT "yaml"');
CALL ModifyColumnIfExists('pod_service', 'spec', 'MEDIUMTEXT COMMENT "yaml"');
CALL ModifyColumnIfExists('pod_group', 'metadata', 'MEDIUMTEXT COMMENT "yaml"');
CALL ModifyColumnIfExists('pod_group', 'spec', 'MEDIUMTEXT COMMENT "yaml"');

UPDATE db_version SET version='7.0.1.25';
