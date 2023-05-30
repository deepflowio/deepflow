CREATE TABLE IF NOT EXISTS prometheus_target (
    id              INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    lcuuid          CHAR(64) DEFAULT '',
    instance        VARCHAR(255) DEFAULT '',
    job             VARCHAR(255) DEFAULT '',
    scrape_url      VARCHAR(2083) DEFAULT '',
    other_labels    TEXT COMMENT 'separated by ,',
    domain          CHAR(64) DEFAULT '',
    sub_domain      CHAR(64) DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at      DATETIME DEFAULT NULL
) ENGINE = innodb DEFAULT CHARSET = utf8mb4 AUTO_INCREMENT = 1;

UPDATE
    db_version
SET
    version = '6.3.1.4';