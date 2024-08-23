CREATE TABLE IF NOT EXISTS alarm_event (
    id                      INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY,
    status                  CHAR(64),
    timestamp               DATETIME,
    end_time                BIGINT,
    policy_id               INTEGER,
    policy_name             TEXT,
    policy_level            INTEGER,
    policy_app_type         TINYINT,
    policy_sub_type         TINYINT,
    policy_contrast_type    TINYINT,
    policy_data_level       CHAR(64),
    policy_target_uid       TEXT,
    policy_target_name      TEXT,
    policy_go_to            TEXT,
    policy_target_field     TEXT,
    policy_endpoints        TEXT,
    sub_view_id             INTEGER,
    sub_view_name           TEXT,
    trigger_condition       TEXT,
    trigger_value           INTEGER,
    end_value               TEXT,
    value_unit              CHAR(64),
    endpoint_results        TEXT,
    lcuuid                  CHAR(64)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;
TRUNCATE TABLE alarm_event;

UPDATE db_version SET version='6.3.1.3';
