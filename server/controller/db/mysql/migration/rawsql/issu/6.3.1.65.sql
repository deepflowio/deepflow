-- modify start, add upgrade sql
DROP PROCEDURE IF EXISTS AddColumnAndSetIfNotExists;

CREATE PROCEDURE AddColumnAndSetIfNotExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255),
    IN defaultVal VARCHAR(255),
    IN afterCol VARCHAR(255)
)
BEGIN
    DECLARE col_count INT;

    -- 检查列是否存在
    SELECT COUNT(*)
    INTO col_count
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_NAME = tableName
    AND COLUMN_NAME = colName;

    -- 如果列不存在，则添加列
    IF col_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' DEFAULT ', defaultVal, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;

    IF tableName = 'vl2_net' THEN
        UPDATE `vl2_net` a INNER JOIN `vl2` b ON a.vl2id = b.id SET a.domain = b.domain;
    END IF;
END;

CALL AddColumnAndSetIfNotExists('vl2_net', 'domain', 'CHAR(64)', '""', 'sub_domain');

DROP PROCEDURE AddColumnAndSetIfNotExists;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.65';
-- modify end