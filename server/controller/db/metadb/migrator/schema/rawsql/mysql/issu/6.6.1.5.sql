-- This template is for upgrade using INSERT/UPDATE/DELETE
-- Tractions are needed for these commands to avoid manual rollback if error occurs.

START TRANSACTION;

/*ALTER TABLE*/
ALTER TABLE plugin
    ADD COLUMN user INTEGER NOT NULL COMMENT '1: agent 2: server';
ALTER TABLE plugin
    ALTER COLUMN user SET DEFAULT 1;
-- update db_version to latest, remember update DB_VERSION_EXPECTED in migration/version.go
UPDATE plugin SET user = 1 WHERE user = 0;
UPDATE db_version SET version='6.6.1.5';
-- modify end

COMMIT;