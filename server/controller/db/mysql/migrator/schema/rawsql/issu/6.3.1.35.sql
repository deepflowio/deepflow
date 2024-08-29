ALTER TABLE alarm_endpoint ADD COLUMN send_title TEXT;

UPDATE db_version SET version='6.3.1.35';

