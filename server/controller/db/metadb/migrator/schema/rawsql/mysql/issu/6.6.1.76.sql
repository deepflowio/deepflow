DELETE FROM process WHERE pod_group_id = 0 OR pod_group_id IS NULL;
DELETE FROM ch_gprocess WHERE id NOT IN (SELECT gid FROM process);
UPDATE db_version SET version='6.6.1.76';
