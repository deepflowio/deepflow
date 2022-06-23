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
	DefaultCKPrimaryAddr     = "tcp://127.0.0.1:9000"
	DefaultThrottle          = 50000
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 10000
	DefaultBrokerQueueSize   = 10000
	DefaultBrokerZMQIP       = "127.0.0.1"
	DefaultBrokerZMQPort     = 20204
	DefaultBrokerZMQHWM      = 1000
)

type Auth struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}
type DBAddr struct {
	Primary string `yaml:"primary"`
	Replica string `yaml:"replica"`
}

type CKAddr struct {
	Primary   string `yaml:"primary"`
	Secondary string `yaml:"secondary"`
}

type CKWriterConfig struct {
	QueueCount   int `yaml:"queue-count"`
	QueueSize    int `yaml:"queue-size"`
	BatchSize    int `yaml:"batch-size"`
	FlushTimeout int `yaml:"flush-timeout"`
}

type FlowLogDisabled struct {
	L4    bool `yaml:"l4"`
	L7    bool `yaml:"l7"`
	Http  bool `yaml:"http"`
	Dns   bool `yaml:"dns"`
	Mysql bool `yaml:"mysql"`
	Redis bool `yaml:"redis"`
	Dubbo bool `yaml:"dubbo"`
	Kafka bool `yaml:"kafka"`
	Mqtt  bool `yaml:"mqtt"`
}

type Config struct {
	ShardID           int             `yaml:"shard-id"`
	ControllerIPs     []string        `yaml:"controller-ips"`
	ControllerPort    int             `yaml:"controller-port"`
	CKDB              CKAddr          `yaml:"ckdb"`
	CKAuth            Auth            `yaml:"ck-auth"`
	ReplicaEnabled    bool            `yaml:"flowlog-replica-enabled"`
	CKWriterConfig    CKWriterConfig  `yaml:"flowlog-ck-writer"`
	Throttle          int             `yaml:"throttle"`
	L4Throttle        int             `yaml:"l4-throttle"`
	L7Throttle        int             `yaml:"l7-throttle"`
	FlowLogDisabled   FlowLogDisabled `yaml:"flow-log-disabled"`
	DecoderQueueCount int             `yaml:"decoder-queue-count"`
	DecoderQueueSize  int             `yaml:"decoder-queue-size"`
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

	if c.ReplicaEnabled && c.CKDB.Secondary == "" {
		return errors.New("'flowlog-replica-enabled' is 'true', but 'ckdb.secondary' is empty")
	}

	return nil
}

func Load(path string) *Config {
	config := &Config{
		ControllerPort:    DefaultControllerPort,
		CKDB:              CKAddr{DefaultCKPrimaryAddr, ""},
		Throttle:          DefaultThrottle,
		DecoderQueueCount: DefaultDecoderQueueCount,
		DecoderQueueSize:  DefaultDecoderQueueSize,
		CKWriterConfig:    CKWriterConfig{QueueCount: 1, QueueSize: 1000000, BatchSize: 512000, FlushTimeout: 10},
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
