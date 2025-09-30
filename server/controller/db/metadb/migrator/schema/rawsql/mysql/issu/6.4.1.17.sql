DROP PROCEDURE IF EXISTS add_prometheus_synced_at;

CREATE PROCEDURE add_prometheus_synced_at()
BEGIN
    DECLARE column_metric_name_synced_at, column_metric_label_synced_at, column_metric_target_synced_at,
    column_metric_app_label_layout_synced_at, column_label_name_synced_at, column_label_synced_at, column_label_value_synced_at CHAR(32) DEFAULT '';

    SELECT COLUMN_NAME INTO column_metric_name_synced_at
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_metric_name'
    AND COLUMN_NAME = 'synced_at';

    IF column_metric_name_synced_at = '' THEN
        ALTER TABLE prometheus_metric_name ADD COLUMN `synced_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;

    SELECT COLUMN_NAME INTO column_metric_label_synced_at
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_metric_label'
    AND COLUMN_NAME = 'synced_at';

    IF column_metric_label_synced_at = '' THEN
        ALTER TABLE prometheus_metric_label ADD COLUMN `synced_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;

    SELECT COLUMN_NAME INTO column_metric_target_synced_at
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_metric_target'
    AND COLUMN_NAME = 'synced_at';

    IF column_metric_target_synced_at = '' THEN
        ALTER TABLE prometheus_metric_target ADD COLUMN `synced_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;

    SELECT COLUMN_NAME INTO column_metric_app_label_layout_synced_at
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_metric_app_label_layout'
    AND COLUMN_NAME = 'synced_at';

    IF column_metric_app_label_layout_synced_at = '' THEN
        ALTER TABLE prometheus_metric_app_label_layout ADD COLUMN `synced_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;

    SELECT COLUMN_NAME INTO column_label_synced_at
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_label'
    AND COLUMN_NAME = 'synced_at';

    IF column_label_synced_at = '' THEN
        ALTER TABLE prometheus_label ADD COLUMN `synced_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;

    SELECT COLUMN_NAME INTO column_label_name_synced_at
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_label_name'
    AND COLUMN_NAME = 'synced_at';

    IF column_label_name_synced_at = '' THEN
        ALTER TABLE prometheus_label_name ADD COLUMN `synced_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;

    SELECT COLUMN_NAME INTO column_label_value_synced_at
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'prometheus_label_value'
    AND COLUMN_NAME = 'synced_at';

    IF column_label_value_synced_at = '' THEN
        ALTER TABLE prometheus_label_value ADD COLUMN `synced_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;
    END IF;

    UPDATE db_version SET version='6.4.1.17';
END;

CALL add_prometheus_synced_at();
