package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("stream.config")

const (
	DefaultControllerIP      = "127.0.0.1"
	DefaultControllerPort    = 20035
	DefaultESHostPort        = "127.0.0.1:20042"
	DefaultThrottle          = 1000
	DefaultOpLoadFactor      = 10
	DefaultRPSplitSize       = 86400 // 1天
	DefaultRPSlots           = 7322
	DefaultRPAliveSlots      = 31
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 100000
	DefaultBrokerQueueSize   = 10000
	DefaultBrokerZMQIP       = "127.0.0.1"
	DefaultBrokerZMQPort     = 20204
	DefaultBrokerZMQHWM      = 1000
)

type ESAuth struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type Config struct {
	ControllerIPs     []string `yaml:"controller-ips"`
	ControllerPort    int      `yaml:"controller-port"`
	ESHostPorts       []string `yaml:"es-host-port"`
	ESAuth            ESAuth   `yaml:"es-auth"`
	Throttle          int      `yaml:"throttle"`
	OpLoadFactor      int      `yaml:"op-load-factor"`
	RPSplitSize       int      `yaml:"rp-split-size"`
	RPSlots           int      `yaml:"rp-slots"`
	RPAliveSlots      int      `yaml:"rp-alive-slots"`
	DecoderQueueCount int      `yaml:"decoder-queue-count"`
	DecoderQueueSize  int      `yaml:"decoder-queue-size"`
	BrokerQueueSize   int      `yaml:"broker-queue-size"`
	BrokerZMQIP       string   `yaml:"broker-zmq-ip"`
	BrokerZMQPort     int      `yaml:"broker-zmq-port"`
	BrokerZMQHWM      int      `yaml:"broker-zmq-hwm"`
	BrokerEnabled     bool     `yaml:"broker-enabled"`
}

func (c *Config) Validate() error {
	for _, ipString := range c.ControllerIPs {
		if net.ParseIP(string(ipString)) == nil {
			return errors.New("controller-ips invalid")
		}
	}

	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}

	return nil
}

func Load(path string) *Config {
	config := &Config{
		ControllerPort:    DefaultControllerPort,
		ESHostPorts:       []string{DefaultESHostPort},
		Throttle:          DefaultThrottle,
		OpLoadFactor:      DefaultOpLoadFactor,
		RPSplitSize:       int(DefaultRPSplitSize),
		RPSlots:           DefaultRPSlots,
		RPAliveSlots:      DefaultRPAliveSlots,
		DecoderQueueCount: DefaultDecoderQueueCount,
		DecoderQueueSize:  DefaultDecoderQueueSize,
		BrokerQueueSize:   DefaultBrokerQueueSize,
		BrokerZMQIP:       DefaultBrokerZMQIP,
		BrokerZMQPort:     DefaultBrokerZMQPort,
		BrokerZMQHWM:      DefaultBrokerZMQHWM,
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return config
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Validate()
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
