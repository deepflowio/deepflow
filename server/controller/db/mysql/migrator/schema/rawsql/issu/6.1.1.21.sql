START TRANSACTION;

-- modify start, add upgrade sql

UPDATE alarm_policy SET level=1 WHERE name="采集器的ERR日志条数超限";
UPDATE alarm_policy SET level=1 WHERE name="K8s容器信息同步滞后";

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.1.1.21';
-- modify end

COMMIT;

