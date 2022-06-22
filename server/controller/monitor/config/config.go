package config

type Warrant struct {
	Host    string `default:"warrant" yaml:"warrant"`
	Port    int    `default:"20413" yaml:"port"`
	Timeout int    `default:"30" yaml:"timeout"`
}

type MonitorConfig struct {
	HealthCheckInterval         int     `default:"60" yaml:"health_check_interval"`
	HealthCheckHandleChannelLen int     `default:"1000" yaml:"health_check_handle_channel_len"`
	LicenseCheckInterval        int     `default:"60" yaml:"license_check_interval"`
	Warrant                     Warrant `yaml:"warrant"`
}
