ALTER TABLE vinterface ADD COLUMN vtap_id INTEGER DEFAULT 0 AFTER netns_id;
ALTER TABLE vinterface ADD COLUMN vtap_id INTEGER AFTER netns_id;

UPDATE db_version SET version='6.3.1.23';

UPDATE db_version SET version='6.3.1.23';