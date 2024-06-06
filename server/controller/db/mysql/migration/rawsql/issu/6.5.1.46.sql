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

CREATE TABLE IF NOT EXISTS `resource_version` (
    `id`            INT(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name`          VARCHAR(255) NOT NULL,
    `version`       INTEGER NOT NULL DEFAULT 0,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

DROP PROCEDURE IF EXISTS InsertData;

CREATE PROCEDURE InsertResourceVersion()
BEGIN
    DECLARE vName CHAR(32) DEFAULT '';
    DECLARE vVersion CHAR(64) DEFAULT '';

    SELECT name
    INTO vName
    FROM resource_version
    WHERE name = 'prometheus';

    IF vName = '' THEN
        SET @prometheus_version = UNIX_TIMESTAMP(NOW());
        INSERT INTO resource_version (name, version) VALUES ('prometheus', @prometheus_version);
    END IF;
END;
CALL InsertResourceVersion();
DROP PROCEDURE InsertResourceVersion;

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.46';
-- modify end
