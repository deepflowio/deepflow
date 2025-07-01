DROP PROCEDURE IF EXISTS DeleteIndexIfExists;

CREATE PROCEDURE DeleteIndexIfExists(
    IN tableName VARCHAR(255),
    IN indexName VARCHAR(255)
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
    -- if index exists, drop index
    IF index_count > 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' DROP INDEX ', indexName);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL DeleteIndexIfExists('process', 'gid_updated_at_index');
CALL DeleteIndexIfExists('ch_chost_cloud_tag', 'id_updated_at_index');
CALL DeleteIndexIfExists('ch_pod_ns_cloud_tag', 'id_updated_at_index');
CALL DeleteIndexIfExists('ch_pod_service_k8s_label', 'id_updated_at_index');
CALL DeleteIndexIfExists('ch_pod_service_k8s_annotation', 'id_updated_at_index');
CALL DeleteIndexIfExists('ch_pod_k8s_env', 'id_updated_at_index');
CALL DeleteIndexIfExists('ch_pod_k8s_label', 'id_updated_at_index');
CALL DeleteIndexIfExists('ch_pod_k8s_annotation', 'id_updated_at_index');

DROP PROCEDURE DeleteIndexIfExists;

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

CALL AddIndexIfNotExists('process', 'domain_sub_domain_gid_updated_at_index', 'domain, sub_domain, gid, updated_at DESC');
CALL AddIndexIfNotExists('ch_chost_cloud_tag', 'domain_id_updated_at_index', 'domain_id, id, updated_at ASC');
CALL AddIndexIfNotExists('ch_pod_ns_cloud_tag', 'domain_sub_domain_id_updated_at_index', 'domain_id, sub_domain_id, id, updated_at ASC');
CALL AddIndexIfNotExists('ch_pod_service_k8s_label', 'domain_sub_domain_id_updated_at_index', 'domain_id, sub_domain_id, id, updated_at ASC');
CALL AddIndexIfNotExists('ch_pod_service_k8s_annotation', 'domain_sub_domain_id_updated_at_index', 'domain_id, sub_domain_id, id, updated_at ASC');
CALL AddIndexIfNotExists('ch_pod_k8s_env', 'domain_sub_domain_id_updated_at_index', 'domain_id, sub_domain_id, id, updated_at ASC');
CALL AddIndexIfNotExists('ch_pod_k8s_label', 'domain_sub_domain_id_updated_at_index', 'domain_id, sub_domain_id, id, updated_at ASC');
CALL AddIndexIfNotExists('ch_pod_k8s_annotation', 'domain_sub_domain_id_updated_at_index', 'domain_id, sub_domain_id, id, updated_at ASC');

DROP PROCEDURE AddIndexIfNotExists;

UPDATE db_version SET version='7.0.1.24';
