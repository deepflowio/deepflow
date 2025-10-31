USE deepflow;

CREATE TABLE IF NOT EXISTS ch_chost_cloud_tags (
    `id`              INTEGER NOT NULL PRIMARY KEY,
    `cloud_tags`      TEXT,
    `updated_at`      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version = '6.2.1.8';