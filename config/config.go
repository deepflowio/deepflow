package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

type Config struct {
	ControllerIps  []string     `yaml:"controller-ips,flow"`
	ControllerPort uint16       `yaml:"controller-port"`
	LogFile        string       `yaml:"log-file"`
	LogLevel       string       `yaml:"log-level"`
	StatsdServer   string       `yaml:"statsd-server"`
	Profiler       bool         `yaml:"profiler"`
	DataInterfaces []string     `yaml:"data-interfaces,flow"`
	TapInterfaces  []string     `yaml:"tap-interfaces,flow"`
	Zeroes         []ZeroConfig `yaml:"zeroes,flow"`
}

type ZeroConfig struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

func (c *Config) Validate() error {
	if len(c.ControllerIps) == 0 {
		return errors.New("controller-ips is empty")
	}

	for _, ipString := range c.ControllerIps {
		if net.ParseIP(string(ipString)) == nil {
			return errors.New("controller-ips invalid")
		}
	}

	if c.LogFile == "" {
		c.LogFile = "/var/log/droplet/droplet.log"
	}
	level := strings.ToLower(c.LogLevel)
	levels := map[string]interface{}{"error": nil, "warn": nil, "info": nil, "debug": nil}
	_, ok := levels[level]
	if ok {
		c.LogLevel = level
	} else {
		c.LogLevel = "info"
	}

	if net.ParseIP(c.StatsdServer) == nil {
		return errors.New("Malformed statsd-server")
	}

	return nil
}

func Load(path string) Config {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Read config file error:", err)
		os.Exit(1)
	}
	config := Config{}
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
