package config

import (
	"io/ioutil"
	"os"
	"reflect"
	"regexp"

	"strings"

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("tracemap")
var Cfg *TraceMapConfig

type Config struct {
	TraceMapConfig TraceMapConfig `yaml:"trace-map"`
}

type TraceMapConfig struct {
	TotalTracesCountMax int     `default:"100000" yaml:"total_traces_count_max"`
	BatchTracesCountMax int     `default:"1000" yaml:"batch_traces_count_max"`
	Querier             Querier `yaml:"querier"`
}

type Querier struct {
	Host string `default:"127.0.0.1" yaml:"host"`
	Port int    `default:"20416" yaml:"port"`
}

func (c *Config) expendEnv() {
	reConfig := reflect.ValueOf(&c.TraceMapConfig)
	reConfig = reConfig.Elem()
	for i := 0; i < reConfig.NumField(); i++ {
		field := reConfig.Field(i)
		switch field.Type().String() {
		case "string":
			fieldStr := field.String()
			pattern := regexp.MustCompile(`\$\{(.+?)\}`)
			p := pattern.FindAllSubmatch([]byte(fieldStr), -1)
			for _, i := range p {
				str := string(i[1])
				fieldStr = strings.Replace(fieldStr, string(i[0]), os.Getenv(str), 1)
			}
			field.SetString(fieldStr)
		}
	}
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
	c.expendEnv()
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := SetDefault(cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return cfg
}
