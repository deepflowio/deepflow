
CREATE TABLE IF NOT EXISTS ch_prometheus_target_label_layout (
    `target_id`           INT(10) NOT NULL PRIMARY KEY,
    `target_label_names`  TEXT,
    `target_label_values` TEXT
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.11';
-- modify end

