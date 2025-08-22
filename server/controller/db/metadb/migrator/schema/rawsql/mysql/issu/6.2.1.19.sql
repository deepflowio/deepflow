START TRANSACTION;

UPDATE data_source SET retention_time = 7 * 24 WHERE name="deepflow_system";

UPDATE db_version SET version = '6.2.1.19';

COMMIT;
