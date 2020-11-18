package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strconv"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")
var ShardID string

const (
	DefaultPrimaryInfluxdbHTTPAddr = "http://127.0.0.1:20044"
	DefaultStoreQueueCount         = 4
	DefaultStoreQueueSize          = 131072
	DefaultStoreBatchBufferSize    = 65536
	DefaultControllerPort          = 20035
	DefaultUnmarshallQueueCount    = 4
	DefaultUnmarshallQueueSize     = 1024
	DefaultDuration                = "170h" // 1w + 2h
	DefaultShardDuration           = "1d"
	DefaultDurationS1              = "26h"
	DefaultShardDurationS1         = "1h"
	DefaultRepairEnabled           = true
	DefaultRepairSyncDelay         = 300
	DefaultRepairInterval          = 60
	DefaultRepairSyncCountOnce     = 200
	DefaultReceiverWindowSize      = 1024
)

type RetentionPolicy struct {
	Duration        string `yaml:"duration"`
	ShardDuration   string `yaml:"shard-duration"`
	DurationS1      string `yaml:"duration-s1"`
	ShardDurationS1 string `yaml:"shard-duration-s1"`
}

type TSDBAddrs struct {
	Primary string `yaml:"primary"`
	Replica string `yaml:"replica"`
}

type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Config struct {
	ShardID                   int             `yaml:"shard-id"`
	TSDB                      TSDBAddrs       `yaml:"tsdb"`
	TSDBAuth                  Auth            `yaml:"tsdb-auth"`
	DisableSecondWrite        bool            `yaml:"disable-second-write"`
	DisableSecondWriteReplica bool            `yaml:"disable-second-write-replica"`
	DisableVtapPacket         bool            `yaml:"disable-vtap-packet"`
	StoreQueueCount           int             `yaml:"store-queue-count"`
	StoreQueueSize            int             `yaml:"store-queue-size"`
	StoreBatchBufferSize      int             `yaml:"store-batch-buffer-size"`
	ControllerIPs             []string        `yaml:"controller-ips"`
	ControllerPort            int             `yaml:"controller-port"`
	UnmarshallQueueCount      int             `yaml:"unmarshall-queue-count"`
	UnmarshallQueueSize       int             `yaml:"unmarshall-queue-size"`
	Retention                 RetentionPolicy `yaml:"influxdb-default-retention-policy"`
	RepairEnabled             bool            `yaml:"repair-enabled"`
	RepairSyncDelay           int             `yaml:"repair-keep-time"`
	RepairInterval            int             `yaml:"repair-interval"`
	RepairSyncCountOnce       int             `yaml:"repair-sync-count-once"`
	ReceiverWindowSize        uint64          `yaml:"receiver-window-size"`
}

func (c *Config) Validate() error {
	for _, ipString := range c.ControllerIPs {
		if net.ParseIP(string(ipString)) == nil {
			return errors.New("controller-ips invalid")
		}
	}

	if c.TSDB.Primary == c.TSDB.Replica {
		return errors.New("in 'tsdb' config, 'primary' is equal to 'replica', it is not allowed")
	}

	if c.ReceiverWindowSize < 64 || c.ReceiverWindowSize > 64*1024 {
		c.ReceiverWindowSize = DefaultReceiverWindowSize
	}

	return nil
}

func Load(path string) *Config {
	configBytes, err := ioutil.ReadFile(path)
	config := &Config{
		ControllerPort:            DefaultControllerPort,
		TSDB:                      TSDBAddrs{DefaultPrimaryInfluxdbHTTPAddr, ""},
		UnmarshallQueueCount:      DefaultUnmarshallQueueCount,
		UnmarshallQueueSize:       DefaultUnmarshallQueueSize,
		StoreQueueCount:           DefaultStoreQueueCount,
		StoreQueueSize:            DefaultStoreQueueSize,
		StoreBatchBufferSize:      DefaultStoreBatchBufferSize,
		Retention:                 RetentionPolicy{DefaultDuration, DefaultShardDuration, DefaultDurationS1, DefaultShardDurationS1},
		RepairEnabled:             DefaultRepairEnabled,
		RepairSyncDelay:           DefaultRepairSyncDelay,
		RepairInterval:            DefaultRepairInterval,
		RepairSyncCountOnce:       DefaultRepairSyncCountOnce,
		ReceiverWindowSize:        DefaultReceiverWindowSize,
		DisableSecondWriteReplica: true,
	}
	if err != nil {
		log.Warningf("Read config file error:", err)
		config.Validate()
		return config
	}
	if err = yaml.Unmarshal(configBytes, config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	ShardID = strconv.Itoa(config.ShardID)
	return config
}

func GetShardID() string {
	if ShardID == "" {
		log.Error("can't get ShardID")
		os.Exit(-1)
	}
	return ShardID
}
