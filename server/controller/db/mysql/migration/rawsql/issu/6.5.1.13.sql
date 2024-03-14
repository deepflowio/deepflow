CREATE TABLE IF NOT EXISTS `team` (
    `id` int(11) unsigned NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `lcuuid` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '',
    `short_lcuuid` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '',
    `org_loop_id` int(11) DEFAULT 1 COMMENT '所属组织复用id',
    `parent_loop_id` int(11) DEFAULT 0 COMMENT '父级团队id，每个组织的default团队无父级，id=0',
    `loop_id` int(11) DEFAULT 0 COMMENT '可复用id（从2开始），default组织（default团队）=1',
    `name` VARCHAR(128) NOT NULL DEFAULT '' COMMENT '',
    `desc` VARCHAR(64) NOT NULL DEFAULT '' COMMENT '',
    `scope` tinyint(1) unsigned DEFAULT 0 COMMENT '团队可见范围。0：组织内可见，1：仅创建者所在团队、上级团队、下级团队的直属成员账号可见',
    `resources` json COMMENT '授权资源',
    `apply_user` json COMMENT '申请加入的用户id列表',
    `owner_user_id` int(11) unsigned NOT NULL DEFAULT 0 COMMENT '创建者（所有者）',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX unique_name (`org_loop_id`,`name`)
) ENGINE=innodb DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;

UPDATE db_version SET version='6.5.1.13';
