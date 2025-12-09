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
CALL AddColumnIfNotExists('alarm_policy', 'comb_policy_lcuuids', "TEXT", 'auto_service_1');

CALL ModifyColumnTypeIfExists('alarm_policy', 'app_type', "TINYINT NOT NULL COMMENT '1-system 3-indicator 4-custom_biz_service 5-comb'");

DROP PROCEDURE ModifyColumnTypeIfExists;
DROP PROCEDURE AddColumnIfNotExists;

UPDATE db_version SET version='7.1.0.17';
