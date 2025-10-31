START TRANSACTION;

ALTER TABLE vtap_group_configuration ADD COLUMN extra_netns_regex TEXT;

UPDATE db_version SET version = '6.1.5.3';

COMMIT;
