-- This template is for upgrade using INSERT/UPDATE/DELETE
-- Tractions are needed for these commands to avoid manual rollback if error occurs.

START TRANSACTION;

/*ALTER TABLE*/
ALTER TABLE ch_pod_node
    ADD COLUMN pod_cluster_id INTEGER;
ALTER TABLE ch_pod_ingress
    ADD COLUMN pod_cluster_id INTEGER;
-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE db_version SET version='6.6.1.7';
-- modify end

COMMIT;