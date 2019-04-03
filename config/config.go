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

	"gitlab.x.lan/yunshan/droplet-libs/datatype"
)

var log = logging.MustGetLogger("config")

type Config struct {
	ControllerIps  []string            `yaml:"controller-ips,flow"`
	ControllerPort uint16              `yaml:"controller-port"`
	LogFile        string              `yaml:"log-file"`
	LogLevel       string              `yaml:"log-level"`
	Profiler       bool                `yaml:"profiler"`
	MaxCPUs        int                 `yaml:"max-cpus"`
	TapInterfaces  []string            `yaml:"tap-interfaces,flow"`
	DefaultTapType uint32              `yaml:"default-tap-type"`
	Stream         string              `yaml:"stream"`
	StreamPort     uint16              `yaml:"stream-port"`
	ZeroPorts      []uint16            `yaml:"zero-ports"`
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
	TimeDiffAdjust    int64 `yaml:"time-diff-adjust"`
	SocketBufferSize  int   `yaml:"socket-buffer-size"`
	OrderingCacheSize int   `yaml:"ordering-cache-size"`
}

type QueueConfig struct {
	QueueSize                   int `yaml:"queue-size"`
	LabelerQueueCount           int `yaml:"labeler-queue-count"`
	LabelerQueueSize            int `yaml:"labeler-queue-size"`
	FlowGeneratorQueueCount     int `yaml:"flow-generator-queue-count"`
	FlowGeneratorQueueSize      int `yaml:"flow-generator-queue-size"`
	MeteringAppQueueCount       int `yaml:"metering-app-queue-count"`
	MeteringAppQueueSize        int `yaml:"metering-app-queue-size"`
	PCapAppQueueCount           int `yaml:"pcap-app-queue-count"`
	PCapAppQueueSize            int `yaml:"pcap-app-queue-size"`
	FlowAppQueueCount           int `yaml:"flow-app-queue-count"`
	FlowAppQueueSize            int `yaml:"flow-app-queue-size"`
	FlowDuplicatorQueueSize     int `yaml:"flow-duplicator-queue-size"`
	DocsQueueSize               int `yaml:"docs-queue-size"`
	MeteringAppOutputQueueCount int `yaml:"metering-app-output-queue-count"`
	MeteringAppOutputQueueSize  int `yaml:"metering-app-output-queue-size"`
	FlowAppOutputQueueCount     int `yaml:"flow-app-output-queue-count"`
	FlowAppOutputQueueSize      int `yaml:"flow-app-output-queue-size"`
	FlowSenderQueueSize         int `yaml:"flow-sender-queue-size"`
	DocSenderQueueSize          int `yaml:"doc_sender_queue_size"`
}

type LabelerConfig struct {
	FastPathDisable bool   `yaml:"fast-path-disable"`
	MapSizeLimit    uint32 `yaml:"map-size-limit"`
}

type PortStatsConfig struct {
	Disable     bool          `yaml:"disable"`
	Interval    time.Duration `yaml:"interval"`
	SrcEndCount int           `yaml:"src-end-count"`
	Timeout     time.Duration `yaml:"timeout"`
}

type FlowGeneratorConfig struct {
	FlowCountLimit int32 `yaml:"flow-count-limit"`
	/* unit of interval and timeout: second */
	ForceReportInterval time.Duration   `yaml:"force-report-interval"`
	EstablishedTimeout  time.Duration   `yaml:"established-timeout"`
	ClosingRstTimeout   time.Duration   `yaml:"closing-rst-timeout"`
	OthersTimeout       time.Duration   `yaml:"others-timeout"`
	FlowCleanInterval   time.Duration   `yaml:"flow-clean-interval"`
	TimeoutCleanerCount uint64          `yaml:"timeout-cleaner-count"`
	HashMapSize         uint64          `yaml:"hash-map-size"`
	ReportTolerance     time.Duration   `yaml:"report-tolerance"`
	IgnoreTorMac        bool            `yaml:"ignore-tor-mac"`
	IgnoreL2End         bool            `yaml:"ignore-l2-end"`
	PortStats           PortStatsConfig `yaml:"port-stats"`
}

type MapReduceConfig struct {
	VariedDocLimit   uint32 `yaml:"varied-doc-limit"`
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

	if c.DefaultTapType == 0 {
		c.DefaultTapType = datatype.PACKET_SOURCE_ISP
	}
	c.Adapter.TimeDiffAdjust *= int64(time.Second)
	if c.Adapter.SocketBufferSize == 0 {
		c.Adapter.SocketBufferSize = 32 * 1024 * 1024
	}
	if c.Adapter.OrderingCacheSize == 0 {
		c.Adapter.OrderingCacheSize = 16
	} else if c.Adapter.OrderingCacheSize > 64 {
		c.Adapter.OrderingCacheSize = 64
	}
	if c.Queue.QueueSize == 0 {
		c.Queue.QueueSize = 65536
	}
	if c.Queue.LabelerQueueCount == 0 {
		c.Queue.LabelerQueueCount = 4
	}
	if c.Queue.LabelerQueueSize == 0 {
		c.Queue.LabelerQueueSize = c.Queue.QueueSize
	}
	if c.Queue.FlowGeneratorQueueCount == 0 {
		c.Queue.FlowGeneratorQueueCount = 4
	}
	if c.Queue.FlowGeneratorQueueSize == 0 {
		c.Queue.FlowGeneratorQueueSize = c.Queue.QueueSize
	}
	if c.Queue.MeteringAppQueueCount == 0 {
		c.Queue.MeteringAppQueueCount = 4
	}
	if c.Queue.MeteringAppQueueSize == 0 {
		c.Queue.MeteringAppQueueSize = c.Queue.QueueSize
	}
	if c.Queue.PCapAppQueueCount <= 0 {
		c.Queue.PCapAppQueueCount = 1
	}
	if c.Queue.PCapAppQueueSize <= 0 {
		c.Queue.PCapAppQueueSize = c.Queue.QueueSize
	}
	if c.Queue.FlowAppQueueCount == 0 {
		c.Queue.FlowAppQueueCount = 2
	}
	if c.Queue.FlowAppQueueSize == 0 {
		c.Queue.FlowAppQueueSize = c.Queue.QueueSize << 3
	}
	if c.Queue.FlowDuplicatorQueueSize == 0 {
		c.Queue.FlowDuplicatorQueueSize = c.Queue.QueueSize << 3
	}
	if c.Queue.DocsQueueSize == 0 {
		c.Queue.DocsQueueSize = 524288
	}
	if c.Queue.MeteringAppOutputQueueCount == 0 {
		c.Queue.MeteringAppOutputQueueCount = 1
	}
	if c.Queue.MeteringAppOutputQueueSize == 0 {
		c.Queue.MeteringAppOutputQueueSize = c.Queue.DocsQueueSize << 1
	}
	if c.Queue.FlowAppOutputQueueCount == 0 {
		c.Queue.FlowAppOutputQueueCount = 1
	}
	if c.Queue.FlowAppOutputQueueSize == 0 {
		c.Queue.FlowAppOutputQueueSize = c.Queue.DocsQueueSize << 3
	}
	if c.Queue.FlowSenderQueueSize == 0 {
		c.Queue.FlowSenderQueueSize = c.Queue.QueueSize << 3
	}
	if c.Queue.DocSenderQueueSize == 0 {
		c.Queue.DocSenderQueueSize = c.Queue.DocsQueueSize << 1
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
	if c.FlowGenerator.FlowCleanInterval == 0 {
		c.FlowGenerator.FlowCleanInterval = time.Second
	} else {
		c.FlowGenerator.FlowCleanInterval *= time.Second
	}
	if c.FlowGenerator.TimeoutCleanerCount == 0 {
		c.FlowGenerator.TimeoutCleanerCount = 4
	}
	if c.FlowGenerator.HashMapSize == 0 {
		c.FlowGenerator.HashMapSize = uint64(c.FlowGenerator.FlowCountLimit) / uint64(c.Queue.FlowGeneratorQueueCount) * 4
	}
	if c.FlowGenerator.ReportTolerance == 0 {
		c.FlowGenerator.ReportTolerance = 4 * time.Second
	} else {
		c.FlowGenerator.ReportTolerance *= time.Second
	}
	if c.FlowGenerator.PortStats.Disable {
		c.FlowGenerator.PortStats.Interval = 0
		c.FlowGenerator.PortStats.SrcEndCount = 0
		c.FlowGenerator.PortStats.Timeout = 0
	} else {
		if c.FlowGenerator.PortStats.Interval == 0 {
			c.FlowGenerator.PortStats.Interval = time.Second
		} else {
			c.FlowGenerator.PortStats.Interval *= time.Second
		}
		if c.FlowGenerator.PortStats.SrcEndCount == 0 {
			c.FlowGenerator.PortStats.SrcEndCount = 5
		}
		if c.FlowGenerator.PortStats.Timeout == 0 {
			c.FlowGenerator.PortStats.Timeout = 300 * time.Second
		} else if c.FlowGenerator.PortStats.Timeout*time.Second < c.FlowGenerator.ClosingRstTimeout {
			log.Error("port-stats-timeout is smaller than closing-rst-timeout")
			os.Exit(1)
		} else {
			c.FlowGenerator.PortStats.Timeout *= time.Second
		}
	}

	if c.MapReduce.VariedDocLimit == 0 {
		c.MapReduce.VariedDocLimit = uint32(c.Queue.DocsQueueSize)
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
