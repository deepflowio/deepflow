DROP PROCEDURE IF EXISTS add_column_iftype;

CREATE PROCEDURE add_column_iftype()
BEGIN
    DECLARE if_type_column CHAR(64) DEFAULT '';

    SELECT COLUMN_NAME INTO if_type_column 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA='deepflow' AND table_name='go_genesis_vinterface' AND COLUMN_NAME='if_type';

    IF if_type_column = '' THEN
        ALTER TABLE go_genesis_vinterface ADD COLUMN if_type CHAR(64) DEFAULT '' AFTER device_type;
    END IF;
    UPDATE db_version SET version='6.4.1.3';
END;

CALL add_column_iftype;
DROP PROCEDURE add_column_iftype;