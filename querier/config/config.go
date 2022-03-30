package config

import (
	"io/ioutil"
	"os"

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("clickhouse")
var Cfg *Config

type Config struct {
	LogFile    string     `default:"/var/log/querier.log" yaml:"log-file"`
	LogLevel   string     `default:"info" yaml:"log-level"`
	ListenPort int        `default:"8086" yaml:"listen-port"`
	Clickhouse Clickhouse `yaml:clickhouse`
}

type Clickhouse struct {
	User           string   `default:"default" yaml:"user"`
	Password       string   `default:"" yaml:"password"`
	Port           int      `default:"9000" yaml:"port"`
	Timeout        int      `default:"60" yaml:"timeout"`
	ConnectTimeout int      `default:"2" yaml:"connect-timeout"`
	IPs            []string `yaml:"ips,flow"`
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

	if err = yaml.Unmarshal(configBytes, c); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = c.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := SetDefault(cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return cfg
}
