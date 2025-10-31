DROP TABLE IF EXISTS ch_app_label;
DROP TABLE IF EXISTS ch_target_label;

CREATE TABLE IF NOT EXISTS ch_app_label (
    `label_name_id`      INT(10) NOT NULL,
    `label_value_id`     INT(10) NOT NULL,
    `label_value`        VARCHAR(256) NOT NULL,
    `updated_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (label_name_id, label_value_id)
)ENGINE=innodb DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS ch_target_label (
    `label_name_id`      INT(10) NOT NULL,
    `target_id`          INT(10) NOT NULL,
    `label_value`        VARCHAR(256) NOT NULL,
    `updated_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (label_name_id, target_id)
)ENGINE=innodb DEFAULT CHARSET=utf8;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.3.1.25';
-- modify end

