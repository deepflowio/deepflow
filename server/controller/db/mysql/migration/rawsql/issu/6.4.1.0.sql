DROP PROCEDURE IF EXISTS add_chpodgroup_podgrouptype;

CREATE PROCEDURE add_chpodgroup_podgrouptype()
BEGIN
    DECLARE pod_group_type_column CHAR(32) DEFAULT '';

    SELECT COLUMN_NAME INTO pod_group_type_column
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'ch_pod_group'
    AND COLUMN_NAME = 'pod_group_type';

    IF pod_group_type_column = '' THEN
        ALTER TABLE `ch_pod_group` ADD COLUMN `pod_group_type` INTEGER DEFAULT NULL AFTER `name`;
        ALTER TABLE `vinterface` ADD COLUMN `vmac` CHAR(32) DEFAULT '' AFTER `mac`;
    END IF;
    UPDATE db_version SET version='6.4.1.0';
END;

CALL add_chpodgroup_podgrouptype();
