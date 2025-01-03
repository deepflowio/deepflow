USE deepflow;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tag (
    `id`            INTEGER NOT NULL,
    `key`           VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256),
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`, `key`)
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.2.1.6';
