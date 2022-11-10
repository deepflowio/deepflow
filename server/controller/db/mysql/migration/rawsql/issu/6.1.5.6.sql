START TRANSACTION;

UPDATE vtap SET license_type=1 where license_type=3;

UPDATE db_version SET version = '6.1.5.6';

COMMIT;
