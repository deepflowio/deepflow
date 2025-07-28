DROP PROCEDURE IF EXISTS ModifyColumnIfExists;

CREATE PROCEDURE ModifyColumnIfExists(
    IN tableName VARCHAR(255),
    IN colName VARCHAR(255),
    IN colType VARCHAR(255)
)
BEGIN
    DECLARE column_count INT;

    SELECT COUNT(*)
    INTO column_count
    FROM information_schema.columns
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = tableName
    AND column_name = colName;

    IF column_count > 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' MODIFY COLUMN ', colName, ' ', colType);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END;

CALL ModifyColumnIfExists('ch_chost_cloud_tag', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');
CALL ModifyColumnIfExists('ch_pod_ns_cloud_tag', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');
CALL ModifyColumnIfExists('ch_pod_service_k8s_label', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');
CALL ModifyColumnIfExists('ch_pod_service_k8s_annotation', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');
CALL ModifyColumnIfExists('ch_pod_k8s_label', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');
CALL ModifyColumnIfExists('ch_pod_k8s_env', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');
CALL ModifyColumnIfExists('ch_pod_k8s_annotation', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');
CALL ModifyColumnIfExists('ch_os_app_tag', '`key`', 'VARCHAR(256) NOT NULL COLLATE utf8_bin');

DROP PROCEDURE ModifyColumnIfExists;

CREATE TABLE IF NOT EXISTS ch_tag_last_updated_at (
    table_name           VARCHAR(64) NOT NULL PRIMARY KEY,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=innodb DEFAULT CHARSET=utf8;

DROP PROCEDURE IF EXISTS InsertTagLastUpdatedAtIfNotExists;

CREATE PROCEDURE InsertTagLastUpdatedAtIfNotExists(
    IN tableName VARCHAR(64)
)
BEGIN
    DECLARE record_count INT;

    SELECT COUNT(*)
    INTO record_count
    FROM ch_tag_last_updated_at
    WHERE table_name = tableName;

    IF record_count = 0 THEN
        INSERT INTO ch_tag_last_updated_at (table_name) VALUES (tableName);
    END IF;
END;

CALL InsertTagLastUpdatedAtIfNotExists('ch_device');
CALL InsertTagLastUpdatedAtIfNotExists('ch_az');
CALL InsertTagLastUpdatedAtIfNotExists('ch_chost');
CALL InsertTagLastUpdatedAtIfNotExists('ch_l3_epc');
CALL InsertTagLastUpdatedAtIfNotExists('ch_subnet');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_cluster');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_ns');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_node');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_ingress');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_service');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_group');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod');
CALL InsertTagLastUpdatedAtIfNotExists('ch_gprocess');
CALL InsertTagLastUpdatedAtIfNotExists('ch_chost_cloud_tag');
CALL InsertTagLastUpdatedAtIfNotExists('ch_chost_cloud_tags');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_ns_cloud_tag');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_ns_cloud_tags');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_service_k8s_label');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_service_k8s_labels');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_service_k8s_annotation');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_service_k8s_annotations');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_k8s_env');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_k8s_envs');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_k8s_label');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_k8s_labels');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_k8s_annotation');
CALL InsertTagLastUpdatedAtIfNotExists('ch_pod_k8s_annotations');
CALL InsertTagLastUpdatedAtIfNotExists('ch_os_app_tag');
CALL InsertTagLastUpdatedAtIfNotExists('ch_os_app_tags');

DROP PROCEDURE InsertTagLastUpdatedAtIfNotExists;

UPDATE db_version SET version='7.0.1.21';
