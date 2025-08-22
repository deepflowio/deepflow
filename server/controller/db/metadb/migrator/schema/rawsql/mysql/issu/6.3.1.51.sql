ALTER TABLE ch_device MODIFY name TEXT;

UPDATE db_version SET version='6.3.1.51';
