ALTER TABLE prometheus_target ADD COLUMN create_method TINYINT(1) DEFAULT 1 COMMENT '1.recorder learning 2.prometheus learning' AFTER sub_domain;

UPDATE db_version SET version='6.3.1.42';
