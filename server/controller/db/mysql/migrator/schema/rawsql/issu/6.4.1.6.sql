DROP TABLE IF EXISTS ch_view_change;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.4.1.6';
-- modify end
