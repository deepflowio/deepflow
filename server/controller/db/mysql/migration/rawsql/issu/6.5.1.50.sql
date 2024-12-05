DROP PROCEDURE IF EXISTS RenameColumnIfExists;

-- 重命名表字段
CREATE PROCEDURE RenameColumnIfExists(
    IN tableName VARCHAR(255),
    IN oldColName VARCHAR(255),
    IN newColName VARCHAR(255),
    IN colType VARCHAR(255),
    IN defaultVal VARCHAR(255)
)
BEGIN
    DECLARE column_exists INT;

    -- 检查 newColName 列是否存在
    SELECT COUNT(*)
    INTO column_exists
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND COLUMN_NAME = newColName;

    -- 如果 newColName 列不存在，则继续检查 oldColName 列
    IF column_exists = 0 THEN
        -- 检查 oldColName 列是否存在
        SELECT COUNT(*)
        INTO column_exists
        FROM information_schema.columns
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = tableName
        AND COLUMN_NAME = oldColName;

        IF column_exists > 0 THEN
            -- 重命名 oldColName 列为 newColName
            SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE COLUMN `', oldColName, '` ', newColName, ' ', colType, ' ', defaultVal);
            PREPARE stmt FROM @sql;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
        END IF;
    END IF;
END;

-- 调用存储过程
CALL RenameColumnIfExists('report_policy', 'interval', 'interval_time', 'enum(''1d'',''1h'')', 'NOT NULL DEFAULT ''1h''');
CALL RenameColumnIfExists('genesis_process', 'user', 'user_name', 'VARCHAR(256)', 'DEFAULT ''''');
CALL RenameColumnIfExists('data_source', 'interval', 'interval_time', 'INTEGER', 'NOT NULL COMMENT ''uint: s''');
CALL RenameColumnIfExists('mail_server', 'user', 'user_name', 'TEXT', 'NOT NULL');

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.50';
-- modify end