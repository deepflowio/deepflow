START TRANSACTION;

UPDATE ch_region SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_az SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_l3_epc SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_subnet SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_cluster SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_node SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_ns SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_group SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_device SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_vtap_port SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_tap_type SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_vtap SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_k8s_label SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_k8s_labels SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_node_port SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_group_port SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_port SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_device_port SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_ip_port SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_server_port SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_ip_relation SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_ip_resource SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_lb_listener SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_ingress SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_node_type SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_string_enum SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_int_enum SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_chost_cloud_tag SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_ns_cloud_tag SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_chost_cloud_tags SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_ns_cloud_tags SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_os_app_tag SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_os_app_tags SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_gprocess SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_service_k8s_label SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_service_k8s_labels SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_k8s_annotation SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_k8s_annotations SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_service_k8s_annotation SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_service_k8s_annotations SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_k8s_env SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_pod_k8s_envs SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_app_label SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_target_label SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_prometheus_label_name SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_prometheus_metric_name SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_prometheus_metric_app_label_layout SET updated_at=CURRENT_TIMESTAMP LIMIT 1;
UPDATE ch_prometheus_target_label_layout SET updated_at=CURRENT_TIMESTAMP LIMIT 1;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.22';
-- modify end

COMMIT;
