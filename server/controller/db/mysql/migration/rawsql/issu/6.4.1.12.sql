ALTER TABLE npb_policy ADD COLUMN direction TINYINT(1) DEFAULT 1 COMMENT '1-all; 2-forward; 3-backward;' AFTER business_id;

-- update db_version to latest, remember update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.4.1.12';
-- modify end
