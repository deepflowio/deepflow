ALTER TABLE resource_group MODIFY COLUMN type INTEGER NOT NULL COMMENT '3: anonymous vm, 4: anonymous ip, 5: anonymous pod, 6: anonymous pod_group, 8: anonymous pod_service, 81: anonymous pod_service as pod_group, 14: anonymous vl2';
ALTER TABLE resource_group_extra_info MODIFY COLUMN resource_type INTEGER NOT NULL COMMENT '1: epc, 2: vm, 3: pod_service, 4: pod_group, 5: vl2, 6: pod_cluster, 7: pod';

DELETE FROM acl WHERE business_id NOT IN (-3, 1);
DELETE FROM group_acl WHERE group_id NOT IN (SELECT id FROM resource_group) OR acl_id NOT IN (SELECT id FROM acl);

UPDATE db_version SET version = '6.1.2.1';
