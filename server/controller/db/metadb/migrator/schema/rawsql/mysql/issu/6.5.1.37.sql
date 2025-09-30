-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS AddIndexIfNotExists;

CREATE PROCEDURE AddIndexIfNotExists()
BEGIN
    DECLARE column_count INT;

    -- 检查列是否存在
    SELECT COUNT(*) 
    INTO column_count
    FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'report'
    AND INDEX_NAME = 'policy_id';

    -- 如果列不存在，则添加
    IF column_count = 0 THEN
        SET @sql = 'ALTER TABLE report ADD INDEX policy_id (policy_id)';
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddIndexIfNotExists();

DROP PROCEDURE AddIndexIfNotExists;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.37';
-- modify end
