ALTER TABLE prometheus_label_value MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;

UPDATE db_version SET version='6.3.1.53';
