package config

import (
	"io/ioutil"
	"os"

	"github.com/metaflowys/metaflow/server/ingester/common"
	"github.com/metaflowys/metaflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")
var ShardID string

const (
	DefaultUnmarshallQueueCount = 4
	DefaultUnmarshallQueueSize  = 10240
	DefaultReceiverWindowSize   = 1024
	DefaultCKReadTimeout        = 300
)

type PCapConfig struct {
	FileDirectory string `yaml:"file-directory"`
}

type CKWriterConfig struct {
	QueueCount   int `yaml:"queue-count"`
	QueueSize    int `yaml:"queue-size"`
	BatchSize    int `yaml:"batch-size"`
	FlushTimeout int `yaml:"flush-timeout"`
}

type Config struct {
	Base                      *config.Config
	CKReadTimeout             int            `yaml:"ck-read-timeout"`
	ReplicaEnabled            bool           `yaml:"metrics-replica-enabled"`
	CKWriterConfig            CKWriterConfig `yaml:"metrics-ck-writer"`
	Pcap                      PCapConfig     `yaml:"pcap"`
	DisableSecondWrite        bool           `yaml:"disable-second-write"`
	DisableSecondWriteReplica bool           `yaml:"disable-second-write-replica"`
	UnmarshallQueueCount      int            `yaml:"unmarshall-queue-count"`
	UnmarshallQueueSize       int            `yaml:"unmarshall-queue-size"`
	ReceiverWindowSize        uint64         `yaml:"receiver-window-size"`
}

type RozeConfig struct {
	Roze Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.ReceiverWindowSize < 64 || c.ReceiverWindowSize > 64*1024 {
		c.ReceiverWindowSize = DefaultReceiverWindowSize
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &RozeConfig{
		Roze: Config{
			Base:                      base,
			CKWriterConfig:            CKWriterConfig{QueueCount: 1, QueueSize: 1000000, BatchSize: 512000, FlushTimeout: 10},
			CKReadTimeout:             DefaultCKReadTimeout,
			UnmarshallQueueCount:      DefaultUnmarshallQueueCount,
			UnmarshallQueueSize:       DefaultUnmarshallQueueSize,
			ReceiverWindowSize:        DefaultReceiverWindowSize,
			DisableSecondWriteReplica: true,

			Pcap: PCapConfig{common.DEFAULT_PCAP_DATA_PATH},
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Roze
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warningf("Read config file error:", err)
		config.Roze.Validate()
		return &config.Roze
	}
	if err = yaml.Unmarshal(configBytes, config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Roze.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	return &config.Roze
}
