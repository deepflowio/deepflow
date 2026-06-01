START TRANSACTION;

UPDATE alarm_endpoint SET push_cycle=0 WHERE push_frequency IS NULL;

UPDATE db_version SET version='7.1.0.41';

COMMIT;
