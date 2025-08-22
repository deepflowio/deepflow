START TRANSACTION;

-- modify start, add upgrade sql

ALTER TABLE ch_pod_k8s_label CHANGE pod_id id INTEGER NOT NULL;
ALTER TABLE ch_pod_k8s_labels CHANGE pod_id id INTEGER NOT NULL;
ALTER TABLE ch_pod_service_k8s_label CHANGE pod_id id INTEGER NOT NULL;
ALTER TABLE ch_pod_service_k8s_labels CHANGE pod_id id INTEGER NOT NULL;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.26';
-- modify end

COMMIT;
