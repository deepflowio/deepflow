START TRANSACTION;

-- modify start, add upgrade sql

DELETE FROM alarm_policy WHERE name="采集器数据丢失 (dispatcher.metrics.retired)";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.39';
-- modify end

COMMIT;
