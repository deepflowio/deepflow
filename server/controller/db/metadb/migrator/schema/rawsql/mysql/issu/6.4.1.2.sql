ALTER TABLE npb_tunnel ADD COLUMN vni_input_type TINYINT(1) DEFAULT 1 COMMENT '1. entire one 2. two parts';

UPDATE db_version SET version='6.4.1.2';
