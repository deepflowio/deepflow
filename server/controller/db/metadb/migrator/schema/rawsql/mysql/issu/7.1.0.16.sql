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

-- UpdateIfColumnExists procedure
DROP PROCEDURE IF EXISTS UpdateIfColumnExists;

CREATE PROCEDURE UpdateIfColumnExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN updateSql TEXT
)
BEGIN
    IF ColumnExists(tableName, colName) THEN
        SET @sql = updateSql;
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL UpdateIfColumnExists('config_map', 'data', 'UPDATE config_map SET data = NULL');
CALL UpdateIfColumnExists('config_map', 'data_hash', 'UPDATE config_map SET data_hash = ''''');
CALL UpdateIfColumnExists('pod_service', 'spec', 'UPDATE pod_service SET spec = NULL');
CALL UpdateIfColumnExists('pod_service', 'spec_hash', 'UPDATE pod_service SET spec_hash = ''''');
CALL UpdateIfColumnExists('pod_service', 'metadata', 'UPDATE pod_service SET metadata = NULL');
CALL UpdateIfColumnExists('pod_service', 'metadata_hash', 'UPDATE pod_service SET metadata_hash = ''''');
CALL UpdateIfColumnExists('pod_group', 'metadata', 'UPDATE pod_group SET metadata = NULL');
CALL UpdateIfColumnExists('pod_group', 'metadata_hash', 'UPDATE pod_group SET metadata_hash = ''''');
CALL UpdateIfColumnExists('pod_group', 'spec', 'UPDATE pod_group SET spec = NULL');
CALL UpdateIfColumnExists('pod_group', 'spec_hash', 'UPDATE pod_group SET spec_hash = ''''');

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

CALL ChangeColumnIfExists('config_map', 'data', 'compressed_data', 'MEDIUMBLOB COMMENT "compressed yaml"');
CALL ChangeColumnIfExists('pod_service', 'metadata', 'compressed_metadata', 'MEDIUMBLOB COMMENT "compressed yaml"');
CALL ChangeColumnIfExists('pod_service', 'spec', 'compressed_spec', 'MEDIUMBLOB COMMENT "compressed yaml"');
CALL ChangeColumnIfExists('pod_group', 'metadata', 'compressed_metadata', 'MEDIUMBLOB COMMENT "compressed yaml"');
CALL ChangeColumnIfExists('pod_group', 'spec', 'compressed_spec', 'MEDIUMBLOB COMMENT "compressed yaml"');

-- Cleanup
DROP FUNCTION IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS UpdateIfColumnExists;
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;

-- Update DB version
UPDATE db_version SET version='7.1.0.16';
