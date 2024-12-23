ALTER TABLE vtap_group_configuration ADD COLUMN proxy_controller_ip VARCHAR(128);
ALTER TABLE vtap_group_configuration ADD COLUMN analyzer_ip VARCHAR(128);

UPDATE db_version SET version = '6.1.6.1';
