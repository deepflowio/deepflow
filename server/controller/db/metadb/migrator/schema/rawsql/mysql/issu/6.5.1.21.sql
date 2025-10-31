
update vtap set team_id=1 where team_id is NULL;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.21';
-- modify end
