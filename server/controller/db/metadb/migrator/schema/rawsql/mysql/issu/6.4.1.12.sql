DROP PROCEDURE IF EXISTS add_npb_policy_direction;

CREATE PROCEDURE add_npb_policy_direction()
BEGIN
    DECLARE column_direction CHAR(32) DEFAULT '';

    SELECT COLUMN_NAME INTO column_direction
    FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'deepflow' AND TABLE_NAME = 'npb_policy'
    AND COLUMN_NAME = 'direction';

    IF column_direction = '' THEN
        ALTER TABLE `npb_policy` ADD COLUMN `direction` TINYINT(1) DEFAULT 1 COMMENT '1-all; 2-forward; 3-backward;' AFTER `business_id`;
    END IF;
    UPDATE db_version SET version='6.4.1.12';
END;

CALL add_npb_policy_direction();
