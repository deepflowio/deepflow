ALTER TABLE vinterface_ip ADD COLUMN vl2_net_id INTEGER DEFAULT 0;
ALTER TABLE ip_resource ADD COLUMN vl2_net_id INTEGER DEFAULT 0;

UPDATE db_version SET version = '6.1.8.13';
