USE deepflow;

ALTER TABLE vtap_group_configuration ADD COLUMN tap_mode INTEGER DEFAULT 0 COMMENT '0: local 1: mirror 2: physical' AFTER capture_bpf;

UPDATE db_version SET version = '6.1.7.0';
