START TRANSACTION;

-- modify start, add upgrade sql

UPDATE domain a, (SELECT JSON_EXTRACT(config, '$.port_name_regex') v, id FROM domain WHERE type=11) b SET a.config = JSON_SET(a.config, '$.node_port_name_regex', b.v) WHERE a.id=b.id;
UPDATE domain a SET a.config = JSON_REMOVE(a.config, '$.port_name_regex') WHERE a.type=11;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.2.1.28';
-- modify end

COMMIT;
