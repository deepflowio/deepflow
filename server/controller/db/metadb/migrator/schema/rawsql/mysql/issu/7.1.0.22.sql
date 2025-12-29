CREATE TABLE IF NOT EXISTS ch_biz_service (
    `id`                 INTEGER NOT NULL PRIMARY KEY,
    `name`               VARCHAR(256),
    `service_group_name` VARCHAR(256),
    `icon_id`            INTEGER,
    `team_id`            INTEGER,
    `domain_id`          INTEGER,
    `updated_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX updated_at_index(`updated_at`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version='7.1.0.22';
