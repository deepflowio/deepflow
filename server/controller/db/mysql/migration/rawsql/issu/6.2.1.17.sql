START TRANSACTION;

UPDATE data_source SET retention_time = retention_time * 24;
UPDATE data_source SET name="flow_log.l4_flow_log", tsdb_type="flow_log.l4_flow_log" WHERE name="flow_log.l4";
UPDATE data_source SET name="flow_log.l7_flow_log", tsdb_type="flow_log.l7_flow_log" WHERE name="flow_log.l7";

set @lcuuid = (select uuid());
INSERT INTO data_source (name, tsdb_type, `interval`, retention_time, lcuuid) VALUES ('flow_log.l4_packet', 'flow_log.l4_packet', 0, 3*24, @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO data_source (name, tsdb_type, `interval`, retention_time, lcuuid) VALUES ('flow_log.l7_packet', 'flow_log.l7_packet', 0, 3*24, @lcuuid);
set @lcuuid = (select uuid());
INSERT INTO data_source (name, tsdb_type, `interval`, retention_time, lcuuid) VALUES ('deepflow_system', 'deepflow_system', 0, 3*24, @lcuuid);

UPDATE db_version SET version = '6.2.1.17';

COMMIT;
