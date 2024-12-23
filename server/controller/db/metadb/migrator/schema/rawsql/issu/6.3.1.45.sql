ALTER TABLE process MODIFY name TEXT;
ALTER TABLE process MODIFY process_name TEXT;
ALTER TABLE go_genesis_process MODIFY name TEXT;
ALTER TABLE go_genesis_process MODIFY process_name TEXT;
ALTER TABLE ch_gprocess MODIFY name TEXT;

UPDATE db_version SET version='6.3.1.45';
