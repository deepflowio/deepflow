package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("ext_metrics.config")

const (
	DefaultControllerIP      = "127.0.0.1"
	DefaultControllerPort    = 20035
	DefaultCKPrimaryAddr     = "tcp://127.0.0.1:9000"
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 100000
	DefaultExtMetricsTTL     = 7
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

type Config struct {
	ControllerIPs     []string       `yaml:"controller-ips"`
	ControllerPort    int            `yaml:"controller-port"`
	CKDB              CKAddr         `yaml:"ckdb"`
	CKAuth            Auth           `yaml:"ck-auth"`
	CKWriterConfig    CKWriterConfig `yaml:"ext-metrics-ck-writer"`
	DecoderQueueCount int            `yaml:"decoder-queue-count"`
	DecoderQueueSize  int            `yaml:"decoder-queue-size"`
	TTL               int            `yaml:"ext-metrics-ttl"`
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
	if c.TTL <= 0 {
		c.TTL = DefaultExtMetricsTTL
	}

	return nil
}

func Load(path string) *Config {
	config := &Config{
		ControllerPort:    DefaultControllerPort,
		CKDB:              CKAddr{DefaultCKPrimaryAddr, ""},
		DecoderQueueCount: DefaultDecoderQueueCount,
		DecoderQueueSize:  DefaultDecoderQueueSize,
		CKWriterConfig:    CKWriterConfig{QueueCount: 1, QueueSize: 100000, BatchSize: 51200, FlushTimeout: 10},
		TTL:               DefaultExtMetricsTTL,
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
