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

CALL AddIndexIfNotExists('ch_region', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_az', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_l3_epc', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_subnet', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_ip_relation', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_cluster', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_node', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_ns', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_group', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_lb_listener', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_ingress', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_k8s_label', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_k8s_labels', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_chost_cloud_tag', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_ns_cloud_tag', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_chost_cloud_tags', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_ns_cloud_tags', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_os_app_tag', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_os_app_tags', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_gprocess', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_service_k8s_label', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_service_k8s_labels', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_k8s_annotation', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_k8s_annotations', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_service_k8s_annotation', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_service_k8s_annotations', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_k8s_env', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_k8s_envs', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_pod_service', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_chost', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_vtap_port', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_vtap', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_tap_type', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_node_type', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_string_enum', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_int_enum', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_app_label', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_target_label', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_prometheus_label_name', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_prometheus_metric_name', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_prometheus_metric_app_label_layout', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_prometheus_target_label_layout', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_policy', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_npb_tunnel', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_alarm_policy', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('ch_user', 'updated_at_index', 'updated_at');
CALL AddIndexIfNotExists('custom_service', 'updated_at_index', 'updated_at');

DROP PROCEDURE AddIndexIfNotExists;

UPDATE db_version SET version='6.6.1.44';
