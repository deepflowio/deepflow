-- This template is for upgrade using CREATE/DROP/ALTER
-- Create a new issue file for each command to avoid manual rollback if error occurs.
-- Do not use transaction because it is not useful for these commands.

-- modify start, add upgrade sql
-- example of simple ALTER TABLE operation
ALTER TABLE go_genesis_ip ADD node_ip CHAR(48) DEFAULT NULL;

-- example with idempotent operation using stored procedures
-- ColumnExists procedure
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

-- Example: Add column if not exists
CALL AddColumnIfNotExists('example_table', 'new_column', 'VARCHAR(256) DEFAULT NULL', 'existing_column');

-- ChangeColumnIfExists procedure for column rename/type change
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
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE COLUMN ', oldColName, ' ', newColName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

-- Example: Change column if exists
CALL ChangeColumnIfExists('example_table', 'old_column_name', 'new_column_name', 'VARCHAR(256) NOT NULL');

-- Cleanup procedures
DROP PROCEDURE IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
DROP PROCEDURE IF EXISTS ChangeColumnIfExists;

-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.1.1.0';
-- modify end
