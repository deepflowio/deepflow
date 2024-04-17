-- modify start, add upgrade sql

ALTER TABLE vtap_repo ADD COLUMN k8s_image VARCHAR(512) DEFAULT '';
ALTER TABLE vtap_repo MODIFY COLUMN image LONGBLOB;
ALTER TABLE vtap_repo MODIFY COLUMN name VARCHAR(512);

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.4.1.31';
-- modify end
