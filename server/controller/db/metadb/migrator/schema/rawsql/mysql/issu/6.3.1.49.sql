DROP PROCEDURE IF EXISTS add_vinterface_vmac;

CREATE PROCEDURE add_vinterface_vmac()
BEGIN
    DECLARE vmac_column CHAR(32) DEFAULT '';

    SELECT COLUMN_NAME INTO vmac_column
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'vinterface'
    AND COLUMN_NAME = 'vmac';

    IF vmac_column = '' THEN
        ALTER TABLE `vinterface` ADD COLUMN `vmac` CHAR(32) DEFAULT '' AFTER `mac`;
    END IF;
    UPDATE db_version SET version='6.3.1.49';
END;

CALL add_vinterface_vmac();
