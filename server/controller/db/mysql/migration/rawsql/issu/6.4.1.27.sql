-- fix kubernetes_cluster invalid updated_time
UPDATE kubernetes_cluster SET updated_time=NULL WHERE updated_time < '1970-01-01 00:00:00';

-- support mysql 8.0, replace MyISAM with InnoDB
ALTER TABLE `genesis_host` ENGINE = InnoDB;
ALTER TABLE `genesis_vm` ENGINE = InnoDB;
ALTER TABLE `genesis_vip` ENGINE = InnoDB;
ALTER TABLE `genesis_vpc` ENGINE = InnoDB;
ALTER TABLE `genesis_network` ENGINE = InnoDB;
ALTER TABLE `genesis_port` ENGINE = InnoDB;
ALTER TABLE `genesis_ip` ENGINE = InnoDB;
ALTER TABLE `genesis_lldp` ENGINE = InnoDB;
ALTER TABLE `genesis_vinterface` ENGINE = InnoDB;
ALTER TABLE `genesis_process` ENGINE = InnoDB;
ALTER TABLE `genesis_storage` ENGINE = InnoDB;

-- update db_version to latest
UPDATE db_version SET version='6.4.1.27';