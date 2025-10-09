START TRANSACTION;

INSERT INTO ch_view_change () VALUES ();

UPDATE db_version SET version='6.3.1.28';

COMMIT;