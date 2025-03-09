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

CALL AddColumnIfNotExists('data_source', 'query_time', "INTEGER DEFAULT 0 COMMENT 'uint: minute'", 'retention_time');

DROP PROCEDURE AddColumnIfNotExists;

DROP PROCEDURE IF EXISTS UpdateQueryTime;

CREATE PROCEDURE UpdateQueryTime(
    IN tableName VARCHAR(255)
)
BEGIN
    -- 动态生成并执行 UPDATE 语句
    SET @update_sql = CONCAT(
        'UPDATE data_source ',
        'SET query_time = 360 ',
        'WHERE data_table_collection = "', tableName, '"'
    );

    -- 准备并执行动态 SQL
    PREPARE stmt FROM @update_sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END;

-- 调用存储过程
CALL UpdateQueryTime('flow_log.l4_flow_log');
CALL UpdateQueryTime('flow_log.l7_flow_log');
CALL UpdateQueryTime('application_log.log');

DROP PROCEDURE UpdateQueryTime;

UPDATE db_version SET version='7.0.1.10';
