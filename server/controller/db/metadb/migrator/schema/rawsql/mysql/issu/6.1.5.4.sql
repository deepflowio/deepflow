START TRANSACTION;

ALTER TABLE alarm_policy MODIFY column deleted_at DATETIME DEFAULT NULL;

UPDATE db_version SET version = '6.1.5.4';

COMMIT;
