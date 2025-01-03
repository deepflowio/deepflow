ALTER TABLE vtap_group_configuration CHANGE prometheus_http_api_address prometheus_http_api_addresses VARCHAR(1024);

UPDATE db_version SET version='6.3.1.40';

