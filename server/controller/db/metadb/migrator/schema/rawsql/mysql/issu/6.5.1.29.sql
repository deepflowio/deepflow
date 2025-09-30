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

    SELECT COUNT(*)
    INTO col_count
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND COLUMN_NAME = colName;

    -- if the column does not exist, add the column
    IF col_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', colName, ' ', colType, ' DEFAULT ', defaultVal, ' AFTER ', afterCol);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddColumnAndSetIfNotExists('npb_policy', 'user_id', 'INTEGER', '1', 'id');
CALL AddColumnAndSetIfNotExists('npb_tunnel', 'user_id', 'INTEGER', '1', 'id');

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.29';
-- modify end
