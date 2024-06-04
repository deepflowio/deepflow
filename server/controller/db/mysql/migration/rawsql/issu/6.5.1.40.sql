UPDATE ip_resource SET vl2_net_id=0;
UPDATE vinterface_ip SET vl2_net_id=0;

-- whether default db or not, update db_version to latest, remember update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.40';
-- modify end
