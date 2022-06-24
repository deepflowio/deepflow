package config

type StatsdConfig struct {
	Host          string `default:"localhost" yaml:"host"`
	Port          string `default:"20040" yaml:"port"`
	FlushInterval int    `default:"30" yaml:"flush_interval"`
}
