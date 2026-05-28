
-- Clean up lb_listener rows whose id exceeds the ID pool upper bound (ResourceMaxID1 default 499999).
-- These IDs cannot be managed by the allocator and must be removed before enabling ID allocation.
DELETE FROM lb_listener WHERE id > 499999;

-- Clean up lb_target_server rows that reference a non-existent lb_listener.
-- This covers both pre-existing orphans and rows whose lb_listener was just removed above.
DELETE FROM lb_target_server
WHERE lb_listener_id NOT IN (SELECT id FROM lb_listener);

-- Update DB version
UPDATE db_version SET version='6.6.1.71';
