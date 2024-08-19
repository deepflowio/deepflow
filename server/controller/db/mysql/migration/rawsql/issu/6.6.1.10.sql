-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS BakColumn;

CREATE PROCEDURE BakColumn(
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
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    -- 如果列不存在，则添加列
    IF column_count != 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' CHANGE COLUMN ', colName, ' ', colName, '_bak ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL BakColumn('vinterface', 'netns_id', 'INTEGER UNSIGNED DEFAULT 0');
CALL BakColumn('vinterface', 'vtap_id', 'INTEGER DEFAULT 0');

DROP PROCEDURE BakColumn;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.6.1.10';
-- modify end
