 ALTER TABLE vtap_group_configuration
    ADD COLUMN wasm_plugins TEXT,
    ADD COLUMN so_plugins TEXT;

-- update db_version to latest, remeber update DB_VERSION_EXPECT in migrate/version.go
UPDATE db_version SET version='6.3.1.59';
-- modify end
