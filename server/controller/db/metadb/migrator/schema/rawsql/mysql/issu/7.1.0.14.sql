DROP PROCEDURE IF EXISTS AddColumnIfNotExists;
DROP PROCEDURE IF EXISTS ModifyColumnTypeIfExists;

CREATE PROCEDURE ModifyColumnTypeIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    SET @sql = CONCAT('ALTER TABLE ', tableName, ' MODIFY COLUMN ', colName, ' ', colType);
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END;

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
CALL AddColumnIfNotExists('alarm_policy', 'auto_service_1', "VARCHAR(256) DEFAULT ''", 'lcuuid');
CALL AddColumnIfNotExists('alarm_policy', 'auto_service_type_1', "INTEGER DEFAULT 0", 'lcuuid');
CALL AddColumnIfNotExists('alarm_policy', 'auto_service_id_1', "INTEGER DEFAULT 0", 'lcuuid');
CALL AddColumnIfNotExists('alarm_policy', 'auto_service_0', "VARCHAR(256) DEFAULT ''", 'lcuuid');
CALL AddColumnIfNotExists('alarm_policy', 'auto_service_type_0', "INTEGER DEFAULT 0", 'lcuuid');
CALL AddColumnIfNotExists('alarm_policy', 'auto_service_id_0', "INTEGER DEFAULT 0", 'lcuuid');
CALL AddColumnIfNotExists('alarm_policy', 'biz_name', "VARCHAR(256) DEFAULT ''", 'lcuuid');
CALL AddColumnIfNotExists('alarm_policy', 'biz_id', "INTEGER DEFAULT 0", 'lcuuid');

CALL ModifyColumnTypeIfExists('alarm_policy', 'app_type', "TINYINT NOT NULL COMMENT '1-system 3-indicator 4-custom_biz_service'");

DROP PROCEDURE ModifyColumnTypeIfExists;
DROP PROCEDURE AddColumnIfNotExists;

UPDATE db_version SET version='7.1.0.14';
