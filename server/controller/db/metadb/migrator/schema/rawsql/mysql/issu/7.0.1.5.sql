START TRANSACTION;

UPDATE pcap_policy p 
JOIN acl a ON p.acl_id = a.id 
SET p.vtap_type = 1 
WHERE a.tap_type = 3;

UPDATE npb_policy n 
JOIN acl a ON n.acl_id = a.id 
SET n.vtap_type = 1 
WHERE a.tap_type = 3;

UPDATE db_version SET version='7.0.1.5';

COMMIT;
