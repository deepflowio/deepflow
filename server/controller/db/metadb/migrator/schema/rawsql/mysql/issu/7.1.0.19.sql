DROP TABLE IF EXISTS ch_alarm_policy;

CREATE TABLE IF NOT EXISTS ch_alarm_policy (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `info`            TEXT,
    `user_id`         INTEGER,
    `team_id`         INTEGER DEFAULT 1,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version='7.1.0.19';
