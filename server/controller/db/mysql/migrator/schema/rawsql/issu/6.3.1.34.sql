ALTER TABLE vtap_group_configuration ADD COLUMN l4_log_ignore_tap_sides TEXT COMMENT 'separate by ","' AFTER l4_log_tap_types;
ALTER TABLE vtap_group_configuration ADD COLUMN l7_log_ignore_tap_sides TEXT COMMENT 'separate by ","' AFTER l4_log_tap_types;

UPDATE db_version SET version='6.3.1.34';

