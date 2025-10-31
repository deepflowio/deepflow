ALTER TABLE alarm_policy ADD COLUMN query_url TEXT;

UPDATE db_version SET version='6.3.1.33';

