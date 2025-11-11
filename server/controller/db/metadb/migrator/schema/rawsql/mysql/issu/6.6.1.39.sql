DROP TABLE IF EXISTS ch_os_app_tag;
DROP TABLE IF EXISTS ch_os_app_tags;

CREATE TABLE IF NOT EXISTS ch_os_app_tag (
    `id`               INTEGER NOT NULL,
    `key`              VARCHAR(256) NOT NULL COLLATE utf8_bin,
    `value`            VARCHAR(256),
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_os_app_tags (
    `id`               INTEGER NOT NULL PRIMARY KEY,
    `os_app_tags`      TEXT,
    `team_id`          INTEGER,
    `domain_id`        INTEGER,
    `sub_domain_id`    INTEGER,
    `updated_at`       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version='6.6.1.39';
