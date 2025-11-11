START TRANSACTION;

UPDATE data_source SET display_name='事件-文件读写事件' where display_name='事件-IO 事件';
UPDATE data_source SET display_name='事件-文件读写指标' where display_name='事件-IO 事件指标';

UPDATE db_version SET version='6.6.1.50';

COMMIT;
