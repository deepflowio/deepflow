START TRANSACTION;

UPDATE data_source SET data_table_collection='event.file_event' where data_table_collection='event.perf_event';

UPDATE db_version SET version='7.0.1.30';

COMMIT;
