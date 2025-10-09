ALTER TABLE prometheus_target ADD COLUMN pod_cluster_id INTEGER AFTER sub_domain;

UPDATE db_version SET version='6.3.1.52';
