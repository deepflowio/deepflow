DROP PROCEDURE IF EXISTS DeletePrometheusMetricLabelNameRows;
CREATE PROCEDURE DeletePrometheusMetricLabelNameRows()
BEGIN
    read_loop: LOOP
        SET @metric_label_name_ids = (SELECT GROUP_CONCAT(id) FROM prometheus_metric_label_name WHERE id NOT IN (SELECT t1.id FROM prometheus_metric_label_name t1 JOIN prometheus_label_name t2 ON t1.label_name_id=t2.id JOIN prometheus_metric_app_label_layout t3 ON t1.metric_name=t3.metric_name AND t2.name=t3.app_label_name));
        IF @metric_label_name_ids IS NULL THEN
            LEAVE read_loop;
        END IF;
        DELETE FROM prometheus_metric_label_name WHERE FIND_IN_SET(id, @metric_label_name_ids);
    END LOOP;
END;

-- modify start, add upgrade sql

DELETE FROM prometheus_target;
DELETE FROM prometheus_metric_target;
DELETE FROM prometheus_metric_app_label_layout WHERE app_label_column_index=0;
CALL DeletePrometheusMetricLabelNameRows();

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/init.go
UPDATE db_version SET version='6.5.1.34';
-- modify end

