DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

CREATE PROCEDURE AddColumnIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    IF column_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnIfNotExists('peer_connection', 'remote_domain', 'CHAR(64) NOT NULL', 'remote_region_id');
CALL AddColumnIfNotExists('peer_connection', 'local_domain', 'CHAR(64) NOT NULL', 'remote_region_id');

DROP PROCEDURE AddColumnIfNotExists;

UPDATE peer_connection SET local_domain = domain;
UPDATE peer_connection SET remote_domain = domain;

DROP PROCEDURE IF EXISTS BackupColumnIfExists;
CREATE PROCEDURE BackupColumnIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255)，
    IN colType VARCHAR(255),
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
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE ', colName, ' ', colName, '_bak ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;
CALL BackupColumnIfExists('peer_connection', 'local_region', 'INTEGER DEFAULT 0');
CALL BackupColumnIfExists('peer_connection', 'remote_region', 'INTEGER DEFAULT 0');

UPDATE db_version SET version='7.0.1.18';
