ALTER TABLE npb_policy ADD COLUMN distribute TINYINT(1) DEFAULT 1 COMMENT '0-drop, 1-distribute' AFTER npb_tunnel_id;

UPDATE db_version SET version = '6.1.2.0';
