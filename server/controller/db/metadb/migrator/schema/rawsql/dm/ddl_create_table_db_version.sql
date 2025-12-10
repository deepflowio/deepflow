-- manage db_version table (creation + reset)
-- execute as a single PL/SQL block for DaMeng
BEGIN

    EXECUTE IMMEDIATE 'CREATE TABLE IF NOT EXISTS db_version (
        "version"             VARCHAR(64) PRIMARY KEY,
        created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )';
    EXECUTE IMMEDIATE 'TRUNCATE TABLE db_version';

    COMMIT;
END;
