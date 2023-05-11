
CREATE TABLE IF NOT EXISTS prometheus_metric_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_label_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_label_value (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `value`         VARCHAR(256) NOT NULL UNIQUE,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_label (
    `id`            INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256) NOT NULL,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX label(name, value)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_metric_app_label_layout (
    `id`                        INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `metric_name`               VARCHAR(256) NOT NULL,
    `app_label_name`            VARCHAR(256) NOT NULL,
    `app_label_column_index`    TINYINT(3) NOT NULL,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX metric_label_index(metric_name, app_label_name)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_metric_target (
    `id`            INT(10) NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `metric_name`   VARCHAR(256) NOT NULL,
    `target_id`     INT(10) NOT NULL,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX metric_target_index(metric_name, target_id)
)ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_target (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `instance`      VARCHAR(256) NOT NULL,
    `job`           INT(10) NOT NULL,
    `other_labels`  TEXT
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version='6.3.1.1';
