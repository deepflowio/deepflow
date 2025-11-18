CREATE TABLE IF NOT EXISTS ch_custom_biz_service (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `name`            VARCHAR(256),
    `uid`             CHAR(64),
    `icon_id`         INTEGER,
    `team_id`         INTEGER DEFAULT 1,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_custom_biz_service_filter (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `client_filter`    TEXT,
    `server_filter`    TEXT,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version='7.1.0.13';
