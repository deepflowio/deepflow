
ALTER TABLE ch_prometheus_target_label_layout MODIFY COLUMN updated_at TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.20';
-- modify end
