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

CALL ChangeColumnIfExists('custom_service', 'resource', 'resources', 'TEXT COMMENT "separated by ,"');

-- Cleanup
DROP PROCEDURE IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;

-- Update DB version
UPDATE db_version SET version='7.1.0.23';
