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

CREATE TABLE IF NOT EXISTS prometheus_metric_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS prometheus_label_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS prometheus_label_value (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `value`         VARCHAR(256) NOT NULL UNIQUE,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS prometheus_label (
    `id`            INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256) NOT NULL,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX label(name, value)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS prometheus_metric_app_label_layout (
    `id`                        INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `metric_name`               VARCHAR(256) NOT NULL,
    `app_label_name`            VARCHAR(256) NOT NULL,
    `app_label_column_index`    TINYINT(3) NOT NULL,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX metric_label_index(metric_name, app_label_name)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

CREATE TABLE IF NOT EXISTS prometheus_metric_target (
    `id`            INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `metric_name`   VARCHAR(256) NOT NULL,
    `target_id`     INT(10) NOT NULL,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX metric_target_index(metric_name, target_id)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

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
    version = '6.3.1.1';
