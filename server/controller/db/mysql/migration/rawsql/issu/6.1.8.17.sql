ALTER TABLE db_version ADD PRIMARY KEY (version);

UPDATE db_version SET version='6.1.8.17';
