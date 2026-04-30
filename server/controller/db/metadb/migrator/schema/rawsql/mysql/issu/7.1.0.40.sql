-- Step 1: Truncate prometheus data tables.
-- Prometheus metrics/labels are re-synced from agents on next startup, so no data
-- migration is needed — a clean slate is both correct and instant.
TRUNCATE TABLE prometheus_metric_name;
TRUNCATE TABLE prometheus_label_name;
TRUNCATE TABLE prometheus_label_value;
TRUNCATE TABLE prometheus_label;
TRUNCATE TABLE prometheus_metric_app_label_layout;
TRUNCATE TABLE ch_app_label;
TRUNCATE TABLE ch_prometheus_label_name;
TRUNCATE TABLE ch_prometheus_metric_app_label_layout;
TRUNCATE TABLE ch_prometheus_metric_name;

-- Step 2: DDL — add name_id, value_id columns to prometheus_label (idempotent).
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

DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

CREATE PROCEDURE AddColumnIfNotExists(
    IN tableName VARCHAR(255),
    IN colName   VARCHAR(255),
    IN colType   VARCHAR(255),
    IN afterCol  VARCHAR(255)
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

CALL AddColumnIfNotExists('prometheus_label', 'name_id',  'INT NOT NULL DEFAULT 0', 'id');
CALL AddColumnIfNotExists('prometheus_label', 'value_id', 'INT NOT NULL DEFAULT 0', 'name_id');

DROP PROCEDURE IF EXISTS ColumnExists;
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

-- Step 3: Add UNIQUE index on (name_id, value_id) before any data is inserted.
-- The tables are truncated below so no deduplication is needed first.
DROP PROCEDURE IF EXISTS AddUniqueIndexIfNotExists;

CREATE PROCEDURE AddUniqueIndexIfNotExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255),
    IN indexDef  VARCHAR(1024)
)
BEGIN
    DECLARE cnt INT;
    SELECT COUNT(*) INTO cnt
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name   = tableName
      AND index_name   = indexName;
    IF cnt = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD UNIQUE INDEX ', indexName, ' ', indexDef);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddUniqueIndexIfNotExists('prometheus_label', 'name_id_value_id_index', '(name_id, value_id)');
DROP PROCEDURE IF EXISTS AddUniqueIndexIfNotExists;

-- Step 4: Rename unused tables to _bak.
DROP PROCEDURE IF EXISTS RenameTableIfExists;

CREATE PROCEDURE RenameTableIfExists(
    IN oldName VARCHAR(255),
    IN newName VARCHAR(255)
)
BEGIN
    DECLARE cnt INT;
    SELECT COUNT(*) INTO cnt
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name   = oldName;
    IF cnt > 0 THEN
        SET @sql = CONCAT('RENAME TABLE ', oldName, ' TO ', newName);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL RenameTableIfExists('prometheus_metric_target',     'prometheus_metric_target_bak');
CALL RenameTableIfExists('prometheus_metric_label_name', 'prometheus_metric_label_name_bak');
DROP PROCEDURE IF EXISTS RenameTableIfExists;

-- Step 4: Drop unused columns.
DROP PROCEDURE IF EXISTS DropColumnIfExists;

CREATE PROCEDURE DropColumnIfExists(
    IN tableName VARCHAR(255),
    IN colName   VARCHAR(255)
)
BEGIN
    DECLARE cnt INT;
    SELECT COUNT(*) INTO cnt
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name   = tableName
      AND column_name  = colName;
    IF cnt > 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' DROP COLUMN ', colName);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL DropColumnIfExists('prometheus_label', 'name');
CALL DropColumnIfExists('prometheus_label', 'value');
DROP PROCEDURE IF EXISTS DropColumnIfExists;

-- Update DB version
UPDATE db_version SET version='7.1.0.40';

