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
CALL AddColumnIfNotExists('alarm_policy', 'dynamic_labels', 'TEXT', 'comb_policy_lcuuids');
CALL AddColumnIfNotExists('alarm_policy', 'static_labels', 'TEXT', 'comb_policy_lcuuids');

-- Cleanup
DROP PROCEDURE IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

-- Update DB version
UPDATE db_version SET version='7.1.0.31';
