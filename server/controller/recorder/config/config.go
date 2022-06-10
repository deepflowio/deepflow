package config

type RecorderConfig struct {
	CacheRefreshInterval         uint16 `default:"3600" yaml:"cache_refresh_interval"`
	DeletedResourceCleanInterval uint16 `default:"24" yaml:"deleted_resource_clean_interval"`
	DeletedResourceRetentionTime uint16 `default:"168" yaml:"deleted_resource_retention_time"`
}
