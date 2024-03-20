-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

CREATE PROCEDURE AddColumnIfNotExists(
    IN dbName VARCHAR(255),
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    -- 检查列是否存在
    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE table_schema = dbName
    AND table_name = tableName
    AND column_name = colName;

    -- 如果列不存在，则添加列
    IF column_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' DEFAULT NULL');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnIfNotExists('deepflow', 'vtap_group_configuration', 'system_load_circuit_breaker_threshold', 'float(8,2)');
CALL AddColumnIfNotExists('deepflow', 'vtap_group_configuration', 'system_load_circuit_breaker_recover', 'float(8,2)');
CALL AddColumnIfNotExists('deepflow', 'vtap_group_configuration', 'system_load_circuit_breaker_metric', 'CHAR(64)');

DROP PROCEDURE AddColumnIfNotExists;



-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.4.1.29';
-- modify end
