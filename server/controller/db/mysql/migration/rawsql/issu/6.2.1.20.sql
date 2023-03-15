ALTER TABLE resource_group ADD COLUMN pod_namespace_id INTEGER AFTER pod_cluster_id;

UPDATE db_version SET version = '6.2.1.20';
