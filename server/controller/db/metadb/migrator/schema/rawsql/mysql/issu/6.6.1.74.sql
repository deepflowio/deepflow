UPDATE alarm_policy SET query_url='/v1/alarm/license-7days/',threshold_error='{"OP":"<=","VALUE":7}' WHERE query_url='/v1/alarm/license-30days/';
UPDATE alarm_policy SET query_url='/v1/alarm/voucher-7days/',threshold_error='{"OP":"<=","VALUE":7}' WHERE query_url='/v1/alarm/voucher-30days/';

UPDATE db_version SET version='6.6.1.74';