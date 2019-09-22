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
	ControllerIps  []string            `yaml:"controller-ips,flow"`
	ControllerPort uint16              `yaml:"controller-port"`
	LogFile        string              `yaml:"log-file"`
	LogLevel       string              `yaml:"log-level"`
	Profiler       bool                `yaml:"profiler"`
	MaxCPUs        int                 `yaml:"max-cpus"`
	Stream         string              `yaml:"stream"`
	StreamPort     uint16              `yaml:"stream-port"`
	ZeroPort       uint16              `yaml:"zero-port"`
	Adapter        AdapterConfig       `yaml:"adapter"`
	Queue          QueueConfig         `yaml:"queue"`
	Labeler        LabelerConfig       `yaml:"labeler"`
	FlowGenerator  FlowGeneratorConfig `yaml:"flow-generator"`
	MapReduce      MapReduceConfig     `yaml:"map-reduce"`
	RpcTimeout     time.Duration       `yaml:"rpc-timeout"`
	PCap           PCapConfig          `yaml:"pcap"`
}

type IpPortConfig struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

type AdapterConfig struct {
	SocketBufferSize  int `yaml:"socket-buffer-size"`
	OrderingCacheSize int `yaml:"ordering-cache-size"`
}

type QueueConfig struct {
	PacketQueueCount int `yaml:"packet-queue-count"`
	FlowQueueCount   int `yaml:"flow-queue-count"`
	DocQueueCount    int `yaml:"doc-queue-count"`

	PacketQueueSize int `yaml:"packet-queue-size"`
	FlowQueueSize   int `yaml:"flow-queue-size"`
	DocQueueSize    int `yaml:"doc-queue-size"`

	LabelerQueueSize               int `yaml:"labeler-queue-size"`
	PCapAppQueueSize               int `yaml:"pcap-app-queue-size"`
	FlowGeneratorQueueSize         int `yaml:"flow-generator-queue-size"`
	MeteringAppQueueSize           int `yaml:"metering-app-queue-size"`
	FlowDuplicatorQueueSize        int `yaml:"flow-duplicator-queue-size"`
	FlowAppQueueSize               int `yaml:"flow-app-queue-size"`
	MeteringDocMarshallerQueueSize int `yaml:"metering-doc-marshaller-queue-size"`
	FlowDocMarshallerQueueSize     int `yaml:"flow-doc-marshaller-queue-size"`
	FlowMarshallerQueueSize        int `yaml:"flow-marshaller-queue-size"`
	FlowSenderQueueSize            int `yaml:"flow-sender-queue-size"`
	DocSenderQueueSize             int `yaml:"doc-sender-queue-size"`
}

type LabelerConfig struct {
	FastPathDisable      bool   `yaml:"fast-path-disable"`
	FirstPathDdbsDisable bool   `yaml:"first-path-ddbs-disable"`
	MapSizeLimit         uint32 `yaml:"map-size-limit"`
}

type FlowGeneratorConfig struct {
	FlowCountLimit int `yaml:"flow-count-limit"`
	/* unit of interval and timeout: second */
	ForceReportInterval time.Duration `yaml:"force-report-interval"`
	EstablishedTimeout  time.Duration `yaml:"established-timeout"`
	ClosingRstTimeout   time.Duration `yaml:"closing-rst-timeout"`
	OthersTimeout       time.Duration `yaml:"others-timeout"`
	HashMapSize         uint64        `yaml:"hash-map-size"`
	ReportTolerance     time.Duration `yaml:"report-tolerance"`
	IgnoreTorMac        bool          `yaml:"ignore-tor-mac"`
	IgnoreL2End         bool          `yaml:"ignore-l2-end"`
}

type MapReduceConfig struct {
	WindowSize       uint32 `yaml:"window-size"`
	WindowMoveMargin uint32 `yaml:"window-move-margin"`
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

	if net.ParseIP(c.Stream) == nil {
		return errors.New("Malformed stream")
	}

	if c.Adapter.SocketBufferSize == 0 {
		c.Adapter.SocketBufferSize = 32 * 1024 * 1024
	}
	if c.Adapter.OrderingCacheSize == 0 {
		c.Adapter.OrderingCacheSize = 16
	} else if c.Adapter.OrderingCacheSize > 256 {
		c.Adapter.OrderingCacheSize = 256
	}

	if c.Queue.PacketQueueCount < 1 || c.Queue.PacketQueueCount > 16 {
		c.Queue.PacketQueueCount = 1
	} else {
		c.Queue.PacketQueueCount = minPowerOfTwo(c.Queue.PacketQueueCount)
	}
	if c.Queue.FlowQueueCount < 1 || c.Queue.FlowQueueCount > 16 {
		c.Queue.FlowQueueCount = 1
	} else {
		c.Queue.FlowQueueCount = minPowerOfTwo(c.Queue.FlowQueueCount)
	}
	if c.Queue.DocQueueCount < 1 || c.Queue.DocQueueCount > 16 {
		c.Queue.DocQueueCount = 1
	} else {
		c.Queue.DocQueueCount = minPowerOfTwo(c.Queue.DocQueueCount)
	}

	if c.Queue.PacketQueueSize < 1<<16 {
		c.Queue.PacketQueueSize = 1 << 16
	}
	if c.Queue.FlowQueueSize < 1<<16 {
		c.Queue.FlowQueueSize = c.Queue.PacketQueueSize << 3
	}
	if c.Queue.DocQueueSize < 1<<16 {
		c.Queue.DocQueueSize = c.Queue.PacketQueueSize << 3
	}

	if c.Queue.LabelerQueueSize <= 0 {
		c.Queue.LabelerQueueSize = c.Queue.PacketQueueSize
	}
	if c.Queue.PCapAppQueueSize <= 0 {
		c.Queue.PCapAppQueueSize = c.Queue.PacketQueueSize
	}
	if c.Queue.FlowGeneratorQueueSize <= 0 {
		c.Queue.FlowGeneratorQueueSize = c.Queue.PacketQueueSize
	}
	if c.Queue.MeteringAppQueueSize <= 0 {
		c.Queue.MeteringAppQueueSize = c.Queue.PacketQueueSize
	}
	if c.Queue.FlowDuplicatorQueueSize <= 0 {
		c.Queue.FlowDuplicatorQueueSize = c.Queue.FlowQueueSize
	}
	if c.Queue.FlowAppQueueSize <= 0 {
		c.Queue.FlowAppQueueSize = c.Queue.FlowQueueSize
	}
	if c.Queue.MeteringDocMarshallerQueueSize <= 0 {
		c.Queue.MeteringDocMarshallerQueueSize = c.Queue.DocQueueSize
	}
	if c.Queue.FlowDocMarshallerQueueSize <= 0 {
		c.Queue.FlowDocMarshallerQueueSize = c.Queue.DocQueueSize
	}
	if c.Queue.FlowMarshallerQueueSize <= 0 {
		c.Queue.FlowMarshallerQueueSize = c.Queue.FlowQueueSize
	}
	if c.Queue.FlowSenderQueueSize <= 0 {
		c.Queue.FlowSenderQueueSize = c.Queue.FlowQueueSize
	}
	if c.Queue.DocSenderQueueSize <= 0 {
		c.Queue.DocSenderQueueSize = c.Queue.DocQueueSize
	}

	if c.Labeler.MapSizeLimit == 0 {
		c.Labeler.MapSizeLimit = 1024 * 1024
	}

	if c.FlowGenerator.FlowCountLimit == 0 {
		c.FlowGenerator.FlowCountLimit = 1024 * 1024
	}
	if c.FlowGenerator.ForceReportInterval == 0 {
		c.FlowGenerator.ForceReportInterval = 60 * time.Second
	} else {
		c.FlowGenerator.ForceReportInterval *= time.Second
	}
	if c.FlowGenerator.EstablishedTimeout == 0 {
		c.FlowGenerator.EstablishedTimeout = 300 * time.Second
	} else {
		c.FlowGenerator.EstablishedTimeout *= time.Second
	}
	if c.FlowGenerator.ClosingRstTimeout == 0 {
		c.FlowGenerator.ClosingRstTimeout = 35 * time.Second
	} else {
		c.FlowGenerator.ClosingRstTimeout *= time.Second
	}
	if c.FlowGenerator.OthersTimeout == 0 {
		c.FlowGenerator.OthersTimeout = 5 * time.Second
	} else {
		c.FlowGenerator.OthersTimeout *= time.Second
	}
	if c.FlowGenerator.HashMapSize == 0 {
		c.FlowGenerator.HashMapSize = uint64(c.FlowGenerator.FlowCountLimit) / uint64(c.Queue.PacketQueueCount) * 4
	}
	if c.FlowGenerator.ReportTolerance == 0 {
		c.FlowGenerator.ReportTolerance = 4 * time.Second
	} else {
		c.FlowGenerator.ReportTolerance *= time.Second
	}

	if c.MapReduce.WindowSize < 70 {
		c.MapReduce.WindowSize = 70
	}
	if c.MapReduce.WindowMoveMargin == 0 {
		c.MapReduce.WindowMoveMargin = 3
	}
	if c.MapReduce.WindowMoveMargin >= c.MapReduce.WindowSize {
		c.MapReduce.WindowMoveMargin = 0
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

	if c.ZeroPort == 0 {
		c.ZeroPort = 20211
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
