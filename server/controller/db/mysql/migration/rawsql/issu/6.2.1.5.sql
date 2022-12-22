
ALTER TABLE ch_string_enum ADD COLUMN description VARCHAR(256);

UPDATE db_version SET version = '6.2.1.5';
