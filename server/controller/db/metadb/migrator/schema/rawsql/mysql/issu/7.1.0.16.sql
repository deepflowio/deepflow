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

-- UpdateIfColumnExists procedure
DROP PROCEDURE IF EXISTS UpdateIfColumnExists;

CREATE PROCEDURE UpdateIfColumnExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN updateSql TEXT
)
BEGIN
    CALL ColumnExists(tableName, colName, @exists);
    IF @exists THEN
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
    CALL ColumnExists(tableName, oldColName, @oldExists);
    CALL ColumnExists(tableName, newColName, @newExists);
    IF @oldExists AND NOT @newExists THEN
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
DROP PROCEDURE IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS UpdateIfColumnExists;
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;

-- Update DB version
UPDATE db_version SET version='7.1.0.16';
