-- for /db/mysql/migration/script/upgrade_vtap_group_config.go
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

CALL AddIndexIfNotExists('vm', 'id_index', '`id`');
CALL AddIndexIfNotExists('vinterface_ip', 'ip_index', '`ip`');
CALL AddIndexIfNotExists('vinterface_ip', 'vifid_index', '`vifid`');
CALL AddIndexIfNotExists('ip_resource', 'ip_index', '`ip`');
CALL AddIndexIfNotExists('ip_resource', 'vifid_index', '`vifid`');
CALL AddIndexIfNotExists('pod', 'domain_index', '`domain`');
CALL AddIndexIfNotExists('pod_service', 'domain_index', '`domain`');
CALL AddIndexIfNotExists('ch_device', 'updated_at_index', '`updated_at`');
CALL AddIndexIfNotExists('ch_pod_k8s_label', 'updated_at_index', '`updated_at`');

DROP PROCEDURE AddIndexIfNotExists;


UPDATE db_version SET version='6.6.1.17';