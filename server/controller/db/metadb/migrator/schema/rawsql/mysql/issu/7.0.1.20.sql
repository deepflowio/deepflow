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

-- Insert data with an ID of 0 to trigger clickhouse synchronization, the synchronization framwork for these tables is tagrecorder subscriber
INSERT IGNORE INTO ch_device (deviceid, devicetype) VALUES (0, 0);
INSERT IGNORE INTO ch_az (id) VALUES (0);
INSERT IGNORE INTO ch_chost (id) VALUES (0);
INSERT IGNORE INTO ch_l3_epc (id) VALUES (0);
INSERT IGNORE INTO ch_subnet (id) VALUES (0);
INSERT IGNORE INTO ch_pod_cluster (id) VALUES (0);
INSERT IGNORE INTO ch_pod_ns (id) VALUES (0);
INSERT IGNORE INTO ch_pod_node (id) VALUES (0);
INSERT IGNORE INTO ch_pod_ingress (id) VALUES (0);
INSERT IGNORE INTO ch_pod_service (id) VALUES (0);
INSERT IGNORE INTO ch_pod_group (id) VALUES (0);
INSERT IGNORE INTO ch_pod (id) VALUES (0);
INSERT IGNORE INTO ch_gprocess (id) VALUES (0);
INSERT IGNORE INTO ch_chost_cloud_tag (id, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_chost_cloud_tags (id) VALUES (0);
INSERT IGNORE INTO ch_pod_ns_cloud_tag (id, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_pod_ns_cloud_tags (id) VALUES (0);
INSERT IGNORE INTO ch_pod_service_k8s_label (id, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_pod_service_k8s_labels (id) VALUES (0);
INSERT IGNORE INTO ch_pod_service_k8s_annotation (id, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_pod_service_k8s_annotations (id) VALUES (0);
INSERT IGNORE INTO ch_pod_k8s_env (id, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_pod_k8s_envs (id) VALUES (0);
INSERT IGNORE INTO ch_pod_k8s_label (id, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_pod_k8s_labels (id) VALUES (0);
INSERT IGNORE INTO ch_pod_k8s_annotation (id, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_pod_k8s_annotations (id) VALUES (0);
INSERT IGNORE INTO ch_os_app_tag (pid, `key`) VALUES (0, '');
INSERT IGNORE INTO ch_os_app_tags (pid) VALUES (0);

UPDATE db_version SET version='7.0.1.20';
