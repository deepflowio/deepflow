package config

type GenesisConfig struct {
	AgingTime               float64  `default:"86400" yaml:"aging_time"`
	VinterfaceAgingTime     float64  `default:"300" yaml:"vinterface_aging_time"`
	LocalIPRanges           []string `yaml:"local_ip_ranges"`
	ExcludeIPRanges         []string `yaml:"exclude_ip_ranges"`
	QueueLengths            int      `default:"60" yaml:"queue_length"`
	DataPersistenceInterval int      `default:"60" yaml:"data_persistence_interval"`
	IPv4CIDRMaxMask         int      `default:"16" yaml:"ipv4_cidr_max_mask"`
	IPv6CIDRMaxMask         int      `default:"64" yaml:"ipv6_cidr_max_mask"`
}
