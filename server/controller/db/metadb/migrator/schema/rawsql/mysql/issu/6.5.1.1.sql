DROP PROCEDURE IF EXISTS add_prometheus_metric_label_name;


CREATE PROCEDURE add_prometheus_metric_label_name()
BEGIN
    DECLARE table_metric_name_value CHAR(32) DEFAULT '';

    SELECT TABLE_NAME INTO table_metric_name_value
    FROM INFORMATION_SCHEMA.TABLES
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_metric_label_name';

    IF table_metric_name_value = '' THEN
        CREATE TABLE IF NOT EXISTS prometheus_metric_label_name (
            `id`                INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `metric_name`       VARCHAR(256) NOT NULL,
            `label_name_id`     INT NOT NULL,
            `synced_at`         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            `created_at`        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX metric_label_name_index(metric_name, label_name_id)
        )ENGINE=innodb AUTO_INCREMENT=1 DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

        INSERT INTO prometheus_metric_label_name (metric_name, label_name_id)
        SELECT DISTINCT a.metric_name, c.id FROM prometheus_metric_label as a, prometheus_label as b, prometheus_label_name as c
        WHERE a.label_id = b.id AND b.name = c.name;

        RENAME TABLE `prometheus_metric_label` TO `prometheus_metric_label_bak`;
    END IF;
    
    UPDATE db_version SET version='6.5.1.1';
END;

CALL add_prometheus_metric_label_name();
