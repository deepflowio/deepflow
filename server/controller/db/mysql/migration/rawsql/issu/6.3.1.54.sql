ALTER TABLE prometheus_label_value DROP INDEX value;
ALTER TABLE prometheus_label_value MODIFY COLUMN value TEXT;
ALTER TABLE prometheus_label DROP INDEX label;
ALTER TABLE prometheus_label MODIFY COLUMN value TEXT;

UPDATE db_version SET version='6.3.1.54';
