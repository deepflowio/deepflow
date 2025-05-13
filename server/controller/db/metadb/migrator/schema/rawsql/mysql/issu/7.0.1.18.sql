UPDATE vtap set license_type = 0, license_functions='' WHERE owner = 'deepflow';

UPDATE db_version SET version='7.0.1.18';
