package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"

	logging "github.com/op/go-logging"
	"server/ingester/common"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")
var ShardID string

const (
	DefaultCKPrimaryAddr        = "tcp://127.0.0.1:9000"
	DefaultControllerPort       = 20035
	DefaultUnmarshallQueueCount = 4
	DefaultUnmarshallQueueSize  = 10240
	DefaultReceiverWindowSize   = 1024
	DefaultCKReadTimeout        = 300
)

type CKAddrs struct {
	Primary   string `yaml:"primary"`
	Secondary string `yaml:"secondary"` // 既可以是primary也可以是replica
}

type Auth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

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
	CKDB                      CKAddrs        `yaml:"ckdb"`
	CKDBAuth                  Auth           `yaml:"ckdb-auth"`
	CKReadTimeout             int            `yaml:"ck-read-timeout"`
	ReplicaEnabled            bool           `yaml:"metrics-replica-enabled"`
	CKWriterConfig            CKWriterConfig `yaml:"metrics-ck-writer"`
	Pcap                      PCapConfig     `yaml:"pcap"`
	DisableSecondWrite        bool           `yaml:"disable-second-write"`
	DisableSecondWriteReplica bool           `yaml:"disable-second-write-replica"`
	ControllerIPs             []string       `yaml:"controller-ips"`
	ControllerPort            int            `yaml:"controller-port"`
	UnmarshallQueueCount      int            `yaml:"unmarshall-queue-count"`
	UnmarshallQueueSize       int            `yaml:"unmarshall-queue-size"`
	ReceiverWindowSize        uint64         `yaml:"receiver-window-size"`
}

func (c *Config) Validate() error {
	for _, ipString := range c.ControllerIPs {
		// 如果controller-ip设置为127.0.0.1，则roze会以127.0.0.1上报分析器IP，trisolaris无法识别出实际的IP，无法注册数据节点
		if ipString == "127.0.0.1" { // 限制controller-ip，不能设置为'127.0.0.1'(如果非要设置，可写为‘127.0.00.1’)
			err := errors.New("'controller-ips' is not allowed set to '127.0.0.1'")
			log.Error(err)
			return err
		}
		if net.ParseIP(string(ipString)) == nil {
			return errors.New("controller-ips invalid")
		}
	}

	if c.CKDB.Primary == c.CKDB.Secondary {
		return errors.New("in 'ckdb' config, 'primary' is equal to 'secondary', it is not allowed")
	}

	if c.ReplicaEnabled && c.CKDB.Secondary == "" {
		return errors.New("'metrics-replica-enabled' is true, but 'ckdb.secondary' is empty")
	}

	if c.ReceiverWindowSize < 64 || c.ReceiverWindowSize > 64*1024 {
		c.ReceiverWindowSize = DefaultReceiverWindowSize
	}

	return nil
}

func Load(path string) *Config {
	config := &Config{
		ControllerPort:            DefaultControllerPort,
		CKDB:                      CKAddrs{DefaultCKPrimaryAddr, ""},
		CKWriterConfig:            CKWriterConfig{QueueCount: 1, QueueSize: 1000000, BatchSize: 512000, FlushTimeout: 10},
		CKReadTimeout:             DefaultCKReadTimeout,
		UnmarshallQueueCount:      DefaultUnmarshallQueueCount,
		UnmarshallQueueSize:       DefaultUnmarshallQueueSize,
		ReceiverWindowSize:        DefaultReceiverWindowSize,
		DisableSecondWriteReplica: true,

		Pcap: PCapConfig{common.DEFAULT_PCAP_DATA_PATH},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return config
	}
	configBytes, err := ioutil.ReadFile(path)
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

	return config
}
