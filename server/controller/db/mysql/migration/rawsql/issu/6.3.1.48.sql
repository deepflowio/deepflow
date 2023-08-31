ALTER TABLE mail_server ADD COLUMN   ntlm_enabled  int;
ALTER TABLE mail_server ADD COLUMN   ntlm_name  TEXT;
ALTER TABLE mail_server ADD COLUMN   ntlm_password  TEXT;

UPDATE db_version SET version='6.3.1.48';

