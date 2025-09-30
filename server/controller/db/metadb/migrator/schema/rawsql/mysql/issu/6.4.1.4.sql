DELETE FROM prometheus_target WHERE create_method=2 AND pod_cluster_id IS NULL;

UPDATE db_version SET version='6.4.1.4';
