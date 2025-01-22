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

CALL AddColumnIfNotExists('pcap_policy', 'vtap_type', "TINYINT(1) COMMENT '1-vtap; 2-vtap_group'", 'acl_id');
CALL AddColumnIfNotExists('pcap_policy', 'vtap_group_ids', "TEXT COMMENT 'separated by ,'", 'vtap_ids');

DROP PROCEDURE AddColumnIfNotExists;

UPDATE db_version SET version='7.0.1.4';
