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
CALL AddColumnIfNotExists('host_device', 'uid', 'CHAR(64) DEFAULT ""', 'extra_info');
CALL AddColumnIfNotExists('pod', 'uid', 'CHAR(64) DEFAULT ""', 'domain');
CALL AddColumnIfNotExists('custom_service', 'service_group_name', 'VARCHAR(128) DEFAULT ""', 'team_id');

-- Cleanup
DROP FUNCTION IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

-- Populate uid columns
UPDATE host_device SET uid = CONCAT('host-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';
UPDATE pod SET uid = CONCAT('pod-', UUID_SHORT()) WHERE uid IS NULL OR uid = '';

-- Update DB version
UPDATE db_version SET version='7.1.0.20';
