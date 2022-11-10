ALTER TABLE vtap_group_configuration
    ADD COLUMN inactive_ip_enabled       TINYINT(1) COMMENT '0: disabled 1:enabled';

UPDATE db_version SET version='6.1.1.1';
