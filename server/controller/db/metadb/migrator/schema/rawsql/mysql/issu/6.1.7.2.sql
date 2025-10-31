USE deepflow;

ALTER TABLE vtap_group_configuration ADD COLUMN tap_mode INTEGER COMMENT '0: local 1: virtual mirror 2: physical mirror' AFTER capture_bpf;

UPDATE db_version SET version = '6.1.7.2';
