ALTER TABLE alarm_endpoint
ADD COLUMN push_cycle INTEGER,
ADD COLUMN push_frequency INTEGER,
ADD COLUMN push_level TEXT,
ADD COLUMN push_level_disable TEXT;

UPDATE db_version SET version='6.3.1.30';

