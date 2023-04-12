START TRANSACTION;

-- modify start, add upgrade sql

ALTER TABLE vtap_group_configuration MODIFY http_log_span_id TEXT DEFAULT NULL;
ALTER TABLE vtap_group_configuration MODIFY http_log_trace_id TEXT DEFAULT NULL;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.1.8.15';
-- modify end

COMMIT;
