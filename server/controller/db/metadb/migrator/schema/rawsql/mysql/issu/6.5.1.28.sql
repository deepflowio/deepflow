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

    -- 检查列是否存在
    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    -- 如果列不存在，则添加列
    IF column_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnIfNotExists('vtap', 'current_k8s_image', 'VARCHAR(512)', 'process_name');
CALL AddColumnIfNotExists('vtap_repo', 'k8s_image', 'VARCHAR(512)', 'image');
CALL AddColumnIfNotExists('vtap_group_configuration', 'max_millicpus', 'VARCHAR(512)', 'max_cpus');

DROP PROCEDURE AddColumnIfNotExists;

ALTER TABLE vtap_repo MODIFY COLUMN image LONGBLOB;
ALTER TABLE vtap_repo MODIFY COLUMN name VARCHAR(512);

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.28';
-- modify end
