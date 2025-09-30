CREATE TABLE IF NOT EXISTS ch_alarm_policy (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `user_id`         INTEGER,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.5.1.8';
-- modify end
