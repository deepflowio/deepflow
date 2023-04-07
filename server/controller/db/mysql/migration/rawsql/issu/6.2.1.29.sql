-- fix the big problem of forgetting to delete process when deleting domain and subdomain (delete only after manual entry)
DELETE FROM process WHERE domain NOT IN(
	SELECT lcuuid FROM domain
);

UPDATE db_version SET version='6.2.1.29';
