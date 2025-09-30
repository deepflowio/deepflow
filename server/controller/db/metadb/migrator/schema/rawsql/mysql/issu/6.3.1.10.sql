
CREATE TABLE IF NOT EXISTS ch_app_label (
    `metric_id`          INT(10) NOT NULL,
    `label_name_id`      INT(10) NOT NULL,
    `label_value_id`     INT(10) NOT NULL,
    `label_value`        VARCHAR(256) NOT NULL,
    PRIMARY KEY (metric_id, label_name_id, label_value_id)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_target_label (
    `metric_id`          INT(10) NOT NULL,
    `label_name_id`      INT(10) NOT NULL,
    `target_id`          INT(10) NOT NULL,
    `label_value`        VARCHAR(256) NOT NULL,
    PRIMARY KEY (metric_id, label_name_id, target_id)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_prometheus_label_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_prometheus_metric_name (
    `id`            INT(10) NOT NULL PRIMARY KEY,
    `name`          VARCHAR(256) NOT NULL
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_prometheus_metric_app_label_layout (
    `id`                        INT(10) NOT NULL PRIMARY KEY,
    `metric_name`               VARCHAR(256) NOT NULL,
    `app_label_name`            VARCHAR(256) NOT NULL,
    `app_label_column_index`    TINYINT(3) UNSIGNED NOT NULL
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.10';
-- modify end

