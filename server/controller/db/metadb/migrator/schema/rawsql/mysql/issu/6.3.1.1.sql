ALTER TABLE vinterface ADD COLUMN netns_id INT UNSIGNED DEFAULT 0 AFTER lcuuid;
ALTER TABLE process ADD COLUMN netns_id INT UNSIGNED DEFAULT 0 AFTER lcuuid;
ALTER TABLE go_genesis_vinterface ADD COLUMN netns_id INT UNSIGNED DEFAULT 0 AFTER id;
ALTER TABLE go_genesis_process ADD COLUMN netns_id INT UNSIGNED DEFAULT 0 AFTER id;

UPDATE db_version SET version='6.3.1.1';
