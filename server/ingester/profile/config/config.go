package config

import (
	"io/ioutil"
	"os"

	"github.com/deepflowio/deepflow/server/ingester/config"
	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("profile.config")

type Config struct {
	Base              *config.Config
	CKWriterConfig    config.CKWriterConfig `yaml:"profile-ck-writer"`
	ProfileTTL        int                   `yaml:"profile-ttl"`
	DecoderQueueCount int                   `yaml:"decoder-queue-count"`
	DecoderQueueSize  int                   `yaml:"decoder-queue-size"`
}

type ProfileConfig struct {
	Profile Config `yaml:"ingester"`
}

const (
	DefaultProfileTTL        = 3 // day
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 1 << 14
)

func (c *Config) Validate() error {
	if c.ProfileTTL <= 0 {
		c.ProfileTTL = DefaultProfileTTL
	}

	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}

	if c.DecoderQueueSize == 0 {
		c.DecoderQueueSize = DefaultDecoderQueueSize
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &ProfileConfig{
		Profile: Config{
			Base:              base,
			CKWriterConfig:    config.CKWriterConfig{QueueCount: 1, QueueSize: 100000, BatchSize: 51200, FlushTimeout: 5},
			ProfileTTL:        DefaultProfileTTL,
			DecoderQueueCount: DefaultDecoderQueueCount,
			DecoderQueueSize:  DefaultDecoderQueueSize,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Profile
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Profile.Validate()
		return &config.Profile
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Profile.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Profile
}
