START TRANSACTION;

set @lcuuid = (select uuid());
INSERT INTO data_source (display_name, data_table_collection, `interval`, retention_time, lcuuid) 
            VALUES ('应用-性能剖析', 'profile.in_process', 0, 3*24, @lcuuid);
UPDATE data_source SET retention_time=7*24 where data_table_collection='ext_metrics.*';
UPDATE data_source SET retention_time=30*24 where data_table_collection='event.event';
UPDATE data_source SET retention_time=7*24 where data_table_collection='event.perf_event';
UPDATE data_source SET retention_time=30*24 where data_table_collection='event.alarm_event';

UPDATE db_version SET version='6.3.1.47';

COMMIT;
