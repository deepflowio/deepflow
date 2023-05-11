
CREATE TABLE IF NOT EXISTS prometheus_metric_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_label_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL UNIQUE
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_label_value (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `value`         VARCHAR(256) NOT NULL UNIQUE
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_label (
    `id`            INT NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL,
    `value`         VARCHAR(256) NOT NULL
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_metric_app_label_layout (
    `id`                        INT(10) NOT NULL PRIMARY KEY,
    `metric_name`               VARCHAR(256) NOT NULL,
    `app_label_name`            VARCHAR(256) NOT NULL,
    `app_label_column_index`    TINYINT(3) NOT NULL,
    UNIQUE INDEX metric_label_index(metric_name, app_label_name)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS prometheus_metric_target (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `metric_name`   VARCHAR(256) NOT NULL,
    `target_id`     INT(10) NOT NULL,
    UNIQUE INDEX metric_target_index(metric_name, target_id)
)ENGINE=innodb DEFAULT CHARSET=utf8;

UPDATE db_version SET version='6.3.1.1';
