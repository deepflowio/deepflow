
ALTER TABLE ch_app_label MODIFY label_value TEXT;

UPDATE db_version SET version='6.3.1.55';
