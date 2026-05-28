
-- Fix match_type default value and reset it for IP/PORT type custom_services
ALTER TABLE custom_service MODIFY COLUMN match_type INTEGER DEFAULT 0 COMMENT '0: none 1: name match 2: uid match';

UPDATE custom_service SET match_type = 0 WHERE type IN (1, 2);

-- Update DB version
UPDATE db_version SET version='6.6.1.70';
