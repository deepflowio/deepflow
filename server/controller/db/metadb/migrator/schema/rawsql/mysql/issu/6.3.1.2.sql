ALTER TABLE vtap_group_configuration ADD COLUMN prometheus_http_api_address VARCHAR(128) AFTER external_agent_http_proxy_port;

UPDATE db_version SET version='6.3.1.2';
