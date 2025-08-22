-- modify start, add upgrade sql
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

CALL AddColumnIfNotExists('vtap', 'enable_features', 'VARCHAR(64) DEFAULT NULL', 'license_functions');
CALL AddColumnIfNotExists('vtap', 'disable_features', 'VARCHAR(64) DEFAULT NULL', 'enable_features');
CALL AddColumnIfNotExists('vtap', 'follow_group_features', 'VARCHAR(64) DEFAULT NULL', 'disable_features');
CALL AddColumnIfNotExists('vtap_group', 'license_functions', 'VARCHAR(64) DEFAULT NULL', 'lcuuid');
CALL AddColumnIfNotExists('license_func_log', 'agent_group_name', 'VARCHAR(64) DEFAULT NULL', 'enabled');
CALL AddColumnIfNotExists('license_func_log', 'agent_group_operation', 'TINYINT(1) DEFAULT NULL', 'agent_group_name');


DROP PROCEDURE IF EXISTS UpdateEnableFeatures;

CREATE PROCEDURE UpdateEnableFeatures()
BEGIN
    DECLARE recordExists INT DEFAULT 0;

    SELECT COUNT(1) INTO recordExists
    FROM consumer_bill
    LIMIT 1;

    IF recordExists > 0 THEN
        UPDATE vtap SET license_functions = '1,2,3,4,5,6,7,8';
        UPDATE vtap SET follow_group_features = '1,2,3,4,5,6,7,8';
        UPDATE vtap SET enable_features = NULL;
        UPDATE vtap SET disable_features = NULL;
        UPDATE vtap_group SET license_functions = '1,2,3,4,5,6,7,8';
    END IF;
END;

CALL UpdateEnableFeatures();

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.12';
-- modify end
