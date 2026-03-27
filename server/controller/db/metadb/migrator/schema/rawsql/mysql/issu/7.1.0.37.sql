DROP PROCEDURE IF EXISTS AddIndexIfNotExists;

CREATE PROCEDURE AddIndexIfNotExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255),
    IN indexCol VARCHAR(255)
)
BEGIN
    DECLARE index_count INT;

    -- check if index exists on the target column (regardless of index name)
    SELECT COUNT(*)
    INTO index_count
    FROM information_schema.statistics
    WHERE table_schema = DATABASE()
    AND table_name = tableName
    AND column_name = indexCol;

    -- if no index on this column, add index
    IF index_count = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD INDEX ', indexName, ' (', indexCol, ') USING BTREE');
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL AddIndexIfNotExists('pod', 'lcuuid_index', 'lcuuid');
CALL AddIndexIfNotExists('pod_group', 'lcuuid_index', 'lcuuid');
CALL AddIndexIfNotExists('pod_group_port', 'lcuuid_index', 'lcuuid');
CALL AddIndexIfNotExists('process', 'lcuuid_index', 'lcuuid');

DROP PROCEDURE AddIndexIfNotExists;

UPDATE db_version SET version='7.1.0.37';
