START TRANSACTION;

alter table consumer_bill  modify column consumption_price float(10,2) DEFAULT NULL;
UPDATE db_version SET version = '6.2.1.15';

COMMIT;
