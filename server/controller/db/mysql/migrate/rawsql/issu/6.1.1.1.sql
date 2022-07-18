/* TODO rolling issu */
USE deepflow;

ALTER TABLE vtap_group_configuration
    ADD COLUMN inactive_ip_enabled       TINYINT(1) COMMENT '0: disabled 1:enabled';
