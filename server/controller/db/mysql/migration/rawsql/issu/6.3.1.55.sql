
ALTER TABLE ch_app_label MODIFY name TEXT;

UPDATE db_version SET version='6.3.1.55';
