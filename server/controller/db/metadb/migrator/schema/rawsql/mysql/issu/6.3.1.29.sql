ALTER TABLE alarm_policy
ADD COLUMN threshold_critical TEXT,
ADD COLUMN threshold_error TEXT,
ADD COLUMN threshold_warning TEXT,
ADD COLUMN trigger_nodata_event TINYINT(1),
ADD COLUMN query_params TEXT,
ADD COLUMN query_conditions TEXT,
ADD COLUMN tag_conditions TEXT,
ADD COLUMN query_method CHAR(64);

UPDATE db_version SET version='6.3.1.29';

