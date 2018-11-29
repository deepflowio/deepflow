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
	"gitlab.x.lan/yunshan/droplet/flowgenerator"
)

var log = logging.MustGetLogger("config")

type Config struct {
	ControllerIps    []string            `yaml:"controller-ips,flow"`
	ControllerPort   uint16              `yaml:"controller-port"`
	LogFile          string              `yaml:"log-file"`
	LogLevel         string              `yaml:"log-level"`
	Profiler         bool                `yaml:"profiler"`
	MaxCPUs          int                 `yaml:"max-cpus"`
	TapInterfaces    []string            `yaml:"tap-interfaces,flow"`
	DefaultTapType   uint32              `yaml:"default-tap-type"`
	AdapterCacheSize int                 `yaml:"adapter-cache-size"`
	Stream           string              `yaml:"stream"`
	StreamPort       uint16              `yaml:"stream-port"`
	ZeroHosts        []string            `yaml:"zero-hosts,flow"`
	ZeroPort         uint16              `yaml:"zero-port"`
	Queue            QueueConfig         `yaml:"queue"`
	Labeler          LabelerConfig       `yaml:"labeler"`
	FlowGenerator    FlowGeneratorConfig `yaml:"flow-generator"`
	MapReduce        MapReduce           `yaml:"map-reduce"`
	RpcTimeout       time.Duration       `yaml:"rpc-timeout"`
}

type IpPortConfig struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

type QueueConfig struct {
	QueueSize                   int `yaml:"queue-size"`
	LabelerQueueCount           int `yaml:"labeler-queue-count"`
	LabelerQueueSize            int `yaml:"labeler-queue-size"`
	FlowGeneratorQueueCount     int `yaml:"flow-generator-queue-count"`
	FlowGeneratorQueueSize      int `yaml:"flow-generator-queue-size"`
	MeteringAppQueueCount       int `yaml:"metering-app-queue-count"`
	MeteringAppQueueSize        int `yaml:"metering-app-queue-size"`
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

type FlowGeneratorConfig struct {
	FlowCountLimit int32 `yaml:"flow-count-limit"`
	/* unit of interval and timeout: second */
	ForceReportInterval time.Duration `yaml:"force-report-interval"`
	EstablishedTimeout  time.Duration `yaml:"established-timeout"`
	ClosingRstTimeout   time.Duration `yaml:"closing-rst-timeout"`
	OthersTimeout       time.Duration `yaml:"others-timeout"`
	TimeoutCleanerCount uint64        `yaml:"timeout-cleaner-count"`
	HashMapSize         uint64        `yaml:"hash-map-size"`
	ReportTolerance     time.Duration `yaml:"report-tolerance"`
}

type MapReduce struct {
	DocsInBuffer uint32 `yaml:"docs-in-buffer"`
	WindowSize   uint32 `yaml:"window-size"`
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

	for _, ipString := range c.ZeroHosts {
		if net.ParseIP(ipString) == nil {
			return errors.New("Malformed zero host")
		}
	}

	if c.DefaultTapType == 0 {
		c.DefaultTapType = datatype.PACKET_SOURCE_TOR
	}
	if c.AdapterCacheSize == 0 {
		c.AdapterCacheSize = 16
	}
	if c.AdapterCacheSize > 64 {
		c.AdapterCacheSize = 64
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
	if c.Queue.FlowAppQueueCount == 0 {
		c.Queue.FlowAppQueueCount = 8
	}
	if c.Queue.FlowAppQueueSize == 0 {
		c.Queue.FlowAppQueueSize = c.Queue.QueueSize
	}
	if c.Queue.FlowDuplicatorQueueSize == 0 {
		c.Queue.FlowDuplicatorQueueSize = c.Queue.FlowGeneratorQueueSize >> 2
	}
	if c.Queue.DocsQueueSize == 0 {
		c.Queue.DocsQueueSize = c.Queue.QueueSize << 1
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
		c.Queue.FlowAppOutputQueueSize = c.Queue.DocsQueueSize << 1
	}
	if c.Queue.FlowSenderQueueSize == 0 {
		c.Queue.FlowSenderQueueSize = c.Queue.QueueSize << 1
	}
	if c.Queue.DocSenderQueueSize == 0 {
		c.Queue.DocSenderQueueSize = int(c.MapReduce.DocsInBuffer) << 1
	}

	if c.Labeler.MapSizeLimit == 0 {
		c.Labeler.MapSizeLimit = 1024 * 1024
	}

	if c.FlowGenerator.FlowCountLimit == 0 {
		c.FlowGenerator.FlowCountLimit = 1024 * 1024
	}
	if c.FlowGenerator.ForceReportInterval == 0 {
		c.FlowGenerator.ForceReportInterval = flowgenerator.FORCE_REPORT_INTERVAL
	} else {
		c.FlowGenerator.ForceReportInterval *= time.Second
	}
	if c.FlowGenerator.EstablishedTimeout == 0 {
		c.FlowGenerator.EstablishedTimeout = flowgenerator.TIMEOUT_ESTABLISHED
	} else {
		c.FlowGenerator.EstablishedTimeout *= time.Second
	}
	if c.FlowGenerator.ClosingRstTimeout == 0 {
		c.FlowGenerator.ClosingRstTimeout = flowgenerator.TIMEOUT_ESTABLISHED_RST
	} else {
		c.FlowGenerator.ClosingRstTimeout *= time.Second
	}
	if c.FlowGenerator.OthersTimeout == 0 {
		c.FlowGenerator.OthersTimeout = flowgenerator.TIMEOUT_EXPCEPTION
	} else {
		c.FlowGenerator.OthersTimeout *= time.Second
	}
	if c.FlowGenerator.TimeoutCleanerCount == 0 {
		c.FlowGenerator.TimeoutCleanerCount = flowgenerator.TIMEOUT_CLEANER_COUNT
	}
	if c.FlowGenerator.HashMapSize == 0 {
		c.FlowGenerator.HashMapSize = flowgenerator.HASH_MAP_SIZE
	}
	if c.FlowGenerator.ReportTolerance == 0 {
		c.FlowGenerator.ReportTolerance = flowgenerator.REPORT_TOLERANCE
	} else {
		c.FlowGenerator.ReportTolerance *= time.Second
	}

	if c.MapReduce.DocsInBuffer == 0 {
		c.MapReduce.DocsInBuffer = 131072
	}
	if c.MapReduce.WindowSize == 0 {
		c.MapReduce.WindowSize = 30
	}
	if c.RpcTimeout > 0 {
		c.RpcTimeout *= time.Second
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
