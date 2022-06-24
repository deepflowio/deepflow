package config

import (
	"io/ioutil"
	"os"

	logging "github.com/op/go-logging"
	"gopkg.in/yaml.v2"

	"server/controller/db/clickhouse"
	"server/controller/db/mysql"
	"server/controller/db/redis"
	genesis "server/controller/genesis/config"
	manager "server/controller/manager/config"
	monitor "server/controller/monitor/config"
	statsd "server/controller/statsd/config"
	tagrecorder "server/controller/tagrecorder/config"
	trisolaris "server/controller/trisolaris/config"
)

var log = logging.MustGetLogger("config")

type Roze struct {
	Port    int `default:"20106" yaml:"port"`
	Timeout int `default:"60" yaml:"timeout"`
}

type Specification struct {
	VTapGroupMax               int `default:"1000" yaml:"vtap_group_max"`
	VTapMaxPerGroup            int `default:"10000" yaml:"vtap_max_per_group"`
	AZMaxPerServer             int `default:"10" yaml:"az_max_per_server"`
	DataSourceMax              int `default:"10" yaml:"data_source_max"`
	DataSourceRetentionTimeMax int `default:"1000" yaml:"data_source_retention_time_max"`
}

type ControllerConfig struct {
	LogFile              string `default:"/var/log/controller.log" yaml:"log-file"`
	LogLevel             string `default:"info" yaml:"log-level"`
	MasterControllerName string `default:"" yaml:"master-controller-name"`

	MySqlCfg      mysql.MySqlConfig           `yaml:"mysql"`
	RedisCfg      redis.RedisConfig           `yaml:"redis"`
	ClickHouseCfg clickhouse.ClickHouseConfig `yaml:"clickhouse"`

	Roze Roze          `yaml:"roze"`
	Spec Specification `yaml:"spec"`

	MonitorCfg     monitor.MonitorConfig         `yaml:"monitor"`
	ManagerCfg     manager.ManagerConfig         `yaml:"manager"`
	GenesisCfg     genesis.GenesisConfig         `yaml:"genesis"`
	StatsdCfg      statsd.StatsdConfig           `yaml:"statsd"`
	TrisolarisCfg  trisolaris.Config             `yaml:"trisolaris"`
	TagRecorderCfg tagrecorder.TagRecorderConfig `yaml:"tagrecorder"`
}

type Config struct {
	ControllerConfig ControllerConfig `yaml:"controller"`
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) Load(path string) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Read config file error:", err, path)
		os.Exit(1)
	}

	if err = yaml.Unmarshal(configBytes, &c); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = c.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	c.ControllerConfig.TrisolarisCfg.LogLevel = c.ControllerConfig.LogLevel
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := SetDefault(cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return cfg
}
