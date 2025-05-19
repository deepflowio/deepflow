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

INSERT INTO ch_tag_last_updated_at (table_name) VALUES
('ch_device'),
('ch_az'),
('ch_chost'),
('ch_l3_epc'),
('ch_subnet'),
('ch_pod_cluster'),
('ch_pod_ns'),
('ch_pod_node'),
('ch_pod_ingress'),
('ch_pod_service'),
('ch_pod_group'),
('ch_pod'),
('ch_gprocess'),
('ch_chost_cloud_tag'),
('ch_chost_cloud_tags'),
('ch_pod_ns_cloud_tag'),
('ch_pod_ns_cloud_tags'),
('ch_pod_service_k8s_label'),
('ch_pod_service_k8s_labels'),
('ch_pod_service_k8s_annotation'),
('ch_pod_service_k8s_annotations'),
('ch_pod_k8s_env'),
('ch_pod_k8s_envs'),
('ch_pod_k8s_label'),
('ch_pod_k8s_labels'),
('ch_pod_k8s_annotation'),
('ch_pod_k8s_annotations'),
('ch_os_app_tag'),
('ch_os_app_tags');

UPDATE db_version SET version='6.6.1.34';
