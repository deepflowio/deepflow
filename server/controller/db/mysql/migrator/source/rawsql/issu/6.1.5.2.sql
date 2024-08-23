START TRANSACTION;

UPDATE controller SET name = node_name;

UPDATE db_version SET version = '6.1.5.2';

COMMIT;
