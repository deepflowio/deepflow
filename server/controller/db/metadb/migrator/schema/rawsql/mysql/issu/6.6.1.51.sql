DROP PROCEDURE IF EXISTS AddIndexIfNotExists;

CREATE PROCEDURE AddIndexIfNotExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255),
    IN indexCol VARCHAR(255)
)
BEGIN
    DECLARE index_count INT;

    -- check if index exists
    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
    AND table_name = tableName
    AND index_name = indexName;

    -- if index not exists, add index
    IF index_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD INDEX ', indexName, ' (', indexCol, ') USING BTREE');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddIndexIfNotExists('genesis_process', 'node_ip_index', 'node_ip');
CALL AddIndexIfNotExists('genesis_vinterface', 'node_ip_index', 'node_ip');

DROP PROCEDURE AddIndexIfNotExists;

UPDATE db_version SET version='6.6.1.51';