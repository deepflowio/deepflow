package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strings"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

type Config struct {
	ControllerIps  []string `yaml:"controller-ips,flow"`
	ControllerPort uint16   `yaml:"controller-port"`
	UDPReadBuffer  int      `yaml:"udp-read-buffer"`
	LogFile        string   `yaml:"log-file"`
	LogLevel       string   `yaml:"log-level"`
	Profiler       bool     `yaml:"profiler"`
	MaxCPUs        int      `yaml:"max-cpus"`
}

func (c *Config) Validate() error {
	if len(c.ControllerIps) == 0 {
		log.Warning("controller-ips is empty")
	} else {
		for _, ipString := range c.ControllerIps {
			if net.ParseIP(ipString) == nil {
				return errors.New("controller-ips invalid")
			}
		}
	}

	level := strings.ToLower(c.LogLevel)
	c.LogLevel = "info"
	for _, l := range []string{"error", "warn", "info", "debug"} {
		if level == l {
			c.LogLevel = l
		}
	}

	return nil
}

func Load(path string) Config {
	configBytes, err := ioutil.ReadFile(path)
	config := Config{
		ControllerPort: 20035,
		UDPReadBuffer:  32 << 20,
		LogFile:        "/var/log/droplet/droplet.log",
	}
	if err != nil {
		config.Validate()
		log.Warning("Read config file error:", err)
		return config
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return config
}
