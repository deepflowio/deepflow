
-- Multiple triggers to update updated_at on each table before update
-- Execute as a single PL/SQL block for DaMeng
-- Marker for the start of executing multiple statements
BEGIN

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_agent_group_configuration_update
    BEFORE UPDATE ON agent_group_configuration
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_az_update
    BEFORE UPDATE ON az
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_cen_update
    BEFORE UPDATE ON cen
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_alarm_policy_update
    BEFORE UPDATE ON ch_alarm_policy
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_app_label_update
    BEFORE UPDATE ON ch_app_label
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_az_update
    BEFORE UPDATE ON ch_az
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_chost_update
    BEFORE UPDATE ON ch_chost
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_chost_cloud_tag_update
    BEFORE UPDATE ON ch_chost_cloud_tag
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_chost_cloud_tags_update
    BEFORE UPDATE ON ch_chost_cloud_tags
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_device_update
    BEFORE UPDATE ON ch_device
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_gprocess_update
    BEFORE UPDATE ON ch_gprocess
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_int_enum_update
    BEFORE UPDATE ON ch_int_enum
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_ip_relation_update
    BEFORE UPDATE ON ch_ip_relation
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_ip_resource_update
    BEFORE UPDATE ON ch_ip_resource
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_l3_epc_update
    BEFORE UPDATE ON ch_l3_epc
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_lb_listener_update
    BEFORE UPDATE ON ch_lb_listener
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_node_type_update
    BEFORE UPDATE ON ch_node_type
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_npb_tunnel_update
    BEFORE UPDATE ON ch_npb_tunnel
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_os_app_tag_update
    BEFORE UPDATE ON ch_os_app_tag
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_os_app_tags_update
    BEFORE UPDATE ON ch_os_app_tags
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_update
    BEFORE UPDATE ON ch_pod
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_cluster_update
    BEFORE UPDATE ON ch_pod_cluster
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_group_update
    BEFORE UPDATE ON ch_pod_group
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_ingress_update
    BEFORE UPDATE ON ch_pod_ingress
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_k8s_annotation_update
    BEFORE UPDATE ON ch_pod_k8s_annotation
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_k8s_annotations_update
    BEFORE UPDATE ON ch_pod_k8s_annotations
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_k8s_env_update
    BEFORE UPDATE ON ch_pod_k8s_env
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_k8s_envs_update
    BEFORE UPDATE ON ch_pod_k8s_envs
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_k8s_label_update
    BEFORE UPDATE ON ch_pod_k8s_label
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_k8s_labels_update
    BEFORE UPDATE ON ch_pod_k8s_labels
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_node_update
    BEFORE UPDATE ON ch_pod_node
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_ns_update
    BEFORE UPDATE ON ch_pod_ns
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_ns_cloud_tag_update
    BEFORE UPDATE ON ch_pod_ns_cloud_tag
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_ns_cloud_tags_update
    BEFORE UPDATE ON ch_pod_ns_cloud_tags
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_service_update
    BEFORE UPDATE ON ch_pod_service
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_service_k8s_annotation_update
    BEFORE UPDATE ON ch_pod_service_k8s_annotation
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_service_k8s_annotations_update
    BEFORE UPDATE ON ch_pod_service_k8s_annotations
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_service_k8s_label_update
    BEFORE UPDATE ON ch_pod_service_k8s_label
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_pod_service_k8s_labels_update
    BEFORE UPDATE ON ch_pod_service_k8s_labels
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_policy_update
    BEFORE UPDATE ON ch_policy
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_prometheus_label_name_update
    BEFORE UPDATE ON ch_prometheus_label_name
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_prometheus_metric_app_label_layout_update
    BEFORE UPDATE ON ch_prometheus_metric_app_label_layout
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_prometheus_metric_name_update
    BEFORE UPDATE ON ch_prometheus_metric_name
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_prometheus_target_label_layout_update
    BEFORE UPDATE ON ch_prometheus_target_label_layout
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_region_update
    BEFORE UPDATE ON ch_region
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_string_enum_update
    BEFORE UPDATE ON ch_string_enum
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_subnet_update
    BEFORE UPDATE ON ch_subnet
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_tap_type_update
    BEFORE UPDATE ON ch_tap_type
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_target_label_update
    BEFORE UPDATE ON ch_target_label
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_user_update
    BEFORE UPDATE ON ch_user
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_vtap_update
    BEFORE UPDATE ON ch_vtap
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ch_vtap_port_update
    BEFORE UPDATE ON ch_vtap_port
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_config_map_update
    BEFORE UPDATE ON config_map
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_custom_service_update
    BEFORE UPDATE ON custom_service
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_data_source_update
    BEFORE UPDATE ON data_source
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_dhcp_port_update
    BEFORE UPDATE ON dhcp_port
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_dial_test_task_update
    BEFORE UPDATE ON dial_test_task
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_domain_update
    BEFORE UPDATE ON "domain"
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_epc_update
    BEFORE UPDATE ON epc
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_floatingip_update
    BEFORE UPDATE ON floatingip
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_host_device_update
    BEFORE UPDATE ON host_device
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_ip_resource_update
    BEFORE UPDATE ON ip_resource
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_lb_update
    BEFORE UPDATE ON lb
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_lb_listener_update
    BEFORE UPDATE ON lb_listener
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_lb_target_server_update
    BEFORE UPDATE ON lb_target_server
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_lb_vm_connection_update
    BEFORE UPDATE ON lb_vm_connection
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_nat_gateway_update
    BEFORE UPDATE ON nat_gateway
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_nat_rule_update
    BEFORE UPDATE ON nat_rule
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_nat_vm_connection_update
    BEFORE UPDATE ON nat_vm_connection
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_npb_tunnel_update
    BEFORE UPDATE ON npb_tunnel
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_peer_connection_update
    BEFORE UPDATE ON peer_connection
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_plugin_update
    BEFORE UPDATE ON plugin
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_update
    BEFORE UPDATE ON pod
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_cluster_update
    BEFORE UPDATE ON pod_cluster
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_group_update
    BEFORE UPDATE ON pod_group
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_group_config_map_connection_update
    BEFORE UPDATE ON pod_group_config_map_connection
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_group_port_update
    BEFORE UPDATE ON pod_group_port
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_ingress_update
    BEFORE UPDATE ON pod_ingress
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_ingress_rule_update
    BEFORE UPDATE ON pod_ingress_rule
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_ingress_rule_backend_update
    BEFORE UPDATE ON pod_ingress_rule_backend
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_namespace_update
    BEFORE UPDATE ON pod_namespace
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_node_update
    BEFORE UPDATE ON pod_node
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_rs_update
    BEFORE UPDATE ON pod_rs
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_service_update
    BEFORE UPDATE ON pod_service
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pod_service_port_update
    BEFORE UPDATE ON pod_service_port
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_process_update
    BEFORE UPDATE ON process
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_rds_instance_update
    BEFORE UPDATE ON rds_instance
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_redis_instance_update
    BEFORE UPDATE ON redis_instance
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_region_update
    BEFORE UPDATE ON region
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_resource_group_update
    BEFORE UPDATE ON resource_group
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_resource_version_update
    BEFORE UPDATE ON resource_version
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_routing_table_update
    BEFORE UPDATE ON routing_table
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_sub_domain_update
    BEFORE UPDATE ON sub_domain
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vinterface_update
    BEFORE UPDATE ON vinterface
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vinterface_ip_update
    BEFORE UPDATE ON vinterface_ip
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vip_update
    BEFORE UPDATE ON vip
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vl2_update
    BEFORE UPDATE ON vl2
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vl2_net_update
    BEFORE UPDATE ON vl2_net
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vm_update
    BEFORE UPDATE ON vm
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vm_pod_node_connection_update
    BEFORE UPDATE ON vm_pod_node_connection
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vnet_update
    BEFORE UPDATE ON vnet
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vtap_group_update
    BEFORE UPDATE ON vtap_group
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_vtap_repo_update
    BEFORE UPDATE ON vtap_repo
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_acl_update
    BEFORE UPDATE ON acl
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_npb_policy_update
    BEFORE UPDATE ON npb_policy
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_alarm_policy_update
    BEFORE UPDATE ON alarm_policy
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_db_version_update
    BEFORE UPDATE ON db_version
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_pcap_policy_update
    BEFORE UPDATE ON pcap_policy
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

    EXECUTE IMMEDIATE 'CREATE OR REPLACE TRIGGER trg_report_policy_update
    BEFORE UPDATE ON report_policy
    FOR EACH ROW
    BEGIN
        :NEW.updated_at := CURRENT_TIMESTAMP;
    END';

-- Marker for the end of executing multiple statements
    COMMIT;
END;