ALTER TABLE alarm_event ADD COLUMN event_level INTEGER;

UPDATE db_version SET version='6.3.1.31';


