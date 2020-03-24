package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

type Config struct {
	ControllerIps  []string      `yaml:"controller-ips,flow"`
	ControllerPort uint16        `yaml:"controller-port"`
	LogFile        string        `yaml:"log-file"`
	LogLevel       string        `yaml:"log-level"`
	Profiler       bool          `yaml:"profiler"`
	MaxCPUs        int           `yaml:"max-cpus"`
	Adapter        AdapterConfig `yaml:"adapter"`
	Labeler        LabelerConfig `yaml:"labeler"`
	Queue          QueueConfig   `yaml:"queue"`
	RpcTimeout     time.Duration `yaml:"rpc-timeout"`
	PCap           PCapConfig    `yaml:"pcap"`
}

type IpPortConfig struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

type AdapterConfig struct {
	SocketBufferSize  int    `yaml:"socket-buffer-size"`
	OrderingCacheSize uint32 `yaml:"ordering-cache-size"`
}

type LabelerConfig struct {
	FastPathDisable bool   `yaml:"fast-path-disable"`
	MapSizeLimit    uint32 `yaml:"map-size-limit"`
}

type QueueConfig struct {
	PacketQueueCount int `yaml:"packet-queue-count"`
	PacketQueueSize  int `yaml:"packet-queue-size"`
}

type PCapConfig struct {
	TCPIPChecksum         bool   `yaml:"tcpip-checksum"`
	BlockSizeKB           int    `yaml:"block-size-kb"`
	MaxConcurrentFiles    int    `yaml:"max-concurrent-files"`
	MaxFileSizeMB         int    `yaml:"max-file-size-mb"`
	MaxFilePeriodSecond   int    `yaml:"max-file-period-second"`
	MaxDirectorySizeGB    int    `yaml:"max-directory-size-gb"`
	DiskFreeSpaceMarginGB int    `yaml:"disk-free-space-margin-gb"`
	MaxFileKeepDay        int    `yaml:"max-file-keep-day"`
	FileDirectory         string `yaml:"file-directory"`
}

func minPowerOfTwo(v int) int {
	for i := uint32(0); i < 30; i++ {
		if v <= 1<<i {
			return 1 << i
		}
	}
	return 1
}

func (c *Config) Validate() error {
	if len(c.ControllerIps) == 0 {
		return errors.New("controller-ips is empty")
	}

	for _, ipString := range c.ControllerIps {
		if net.ParseIP(ipString) == nil {
			return errors.New("controller-ips invalid")
		}
	}

	if c.LogFile == "" {
		c.LogFile = "/var/log/droplet/droplet.log"
	}
	level := strings.ToLower(c.LogLevel)
	c.LogLevel = "info"
	for _, l := range []string{"error", "warn", "info", "debug"} {
		if level == l {
			c.LogLevel = l
		}
	}

	if c.Adapter.SocketBufferSize == 0 {
		c.Adapter.SocketBufferSize = 32 * 1024 * 1024
	}
	if c.Adapter.OrderingCacheSize < 64 {
		c.Adapter.OrderingCacheSize = 64
	} else if c.Adapter.OrderingCacheSize > 1024 {
		c.Adapter.OrderingCacheSize = 1024
	}

	if c.Labeler.MapSizeLimit == 0 {
		c.Labeler.MapSizeLimit = 1024 * 1024
	}

	if c.Queue.PacketQueueCount < 1 || c.Queue.PacketQueueCount > 16 {
		c.Queue.PacketQueueCount = 1
	} else {
		c.Queue.PacketQueueCount = minPowerOfTwo(c.Queue.PacketQueueCount)
	}
	if c.Queue.PacketQueueSize < 1<<16 {
		c.Queue.PacketQueueSize = 1 << 16
	}

	if c.RpcTimeout > 0 {
		c.RpcTimeout *= time.Second
	}

	if c.PCap.BlockSizeKB <= 0 {
		c.PCap.BlockSizeKB = 64
	}
	if c.PCap.MaxConcurrentFiles <= 0 {
		c.PCap.MaxConcurrentFiles = 5000
	}
	if c.PCap.MaxFileSizeMB <= 0 {
		c.PCap.MaxFileSizeMB = 25
	}
	if c.PCap.MaxFilePeriodSecond <= 0 {
		c.PCap.MaxFilePeriodSecond = 300
	}
	if c.PCap.MaxDirectorySizeGB <= 0 {
		c.PCap.MaxDirectorySizeGB = 100
	}
	if c.PCap.DiskFreeSpaceMarginGB <= 0 {
		c.PCap.DiskFreeSpaceMarginGB = 10
	}
	if c.PCap.MaxFileKeepDay <= 0 {
		c.PCap.MaxFileKeepDay = 7
	}
	if c.PCap.FileDirectory == "" {
		c.PCap.FileDirectory = "/var/lib/droplet/pcap"
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
