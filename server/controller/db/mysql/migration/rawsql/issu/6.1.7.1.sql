USE deepflow;

ALTER TABLE vtap_group_configuration DROP COLUMN tap_mode;

UPDATE db_version SET version = '6.1.7.1';
