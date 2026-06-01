START TRANSACTION;

UPDATE alarm_endpoint SET push_cycle=0 WHERE push_frequency IS NULL;

UPDATE db_version SET version='6.6.1.72';

COMMIT;
