DROP PROCEDURE IF EXISTS BackupTable;

CREATE PROCEDURE BackupTable(
    IN tableName VARCHAR(255)
)
BEGIN
    DECLARE tName CHAR(32) DEFAULT '';

    SELECT TABLE_NAME
    INTO tName
    FROM INFORMATION_SCHEMA.TABLES
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName;

    -- if the column does not exist, add the column
    IF tName = tableName THEN
        SET @sql = CONCAT('RENAME TABLE ', tableName, ' TO ', tableName, '_bak');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL BackupTable('prometheus_metric_label_name');
CALL BackupTable('prometheus_metric_target');
CALL BackupTable('prometheus_target');

DROP PROCEDURE BackupTable;

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.46';
-- modify end
