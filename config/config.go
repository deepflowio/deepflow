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

	"gitlab.x.lan/yunshan/droplet/flowgenerator"
)

var log = logging.MustGetLogger("config")

type Config struct {
	ControllerIps  []string            `yaml:"controller-ips,flow"`
	ControllerPort uint16              `yaml:"controller-port"`
	LogFile        string              `yaml:"log-file"`
	LogLevel       string              `yaml:"log-level"`
	Profiler       bool                `yaml:"profiler"`
	TapInterfaces  []string            `yaml:"tap-interfaces,flow"`
	Stream         string              `yaml:"stream"`
	StreamPort     uint16              `yaml:"stream-port"`
	ZeroHosts      []string            `yaml:"zero-hosts,flow"`
	ZeroPort       uint16              `yaml:"zero-port"`
	Queue          QueueConfig         `yaml:"queue"`
	Labeler        LabelerConfig       `yaml:"labeler"`
	FlowGenerator  FlowGeneratorConfig `yaml:"flow-generator"`
	MapReduce      MapReduce           `yaml:"map-reduce"`
}

type IpPortConfig struct {
	Ip   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

type QueueConfig struct {
	QueueSize               uint32 `yaml:"queue-size"`
	LabelerQueueCount       uint32 `yaml:"labeler-queue-count"`
	FlowGeneratorQueueCount uint32 `yaml:"flow-generator-queue-count"`
	MeteringAppQueueCount   uint32 `yaml:"metering-app-queue-count"`
	FlowAppQueueCount       uint32 `yaml:"flow-app-queue-count"`
}

type LabelerConfig struct {
	MapSizeLimit uint32 `yaml:"map-size-limit"`
}

type FlowGeneratorConfig struct {
	FlowCountLimit uint32 `yaml:"flow-count-limit"`
	/* unit of interval and timeout: second */
	ForceReportInterval time.Duration `yaml:"force-report-interval"`
	EstablishedTimeout  time.Duration `yaml:"established-timeout"`
	ClosingRstTimeout   time.Duration `yaml:"closing-rst-timeout"`
	OthersTimeout       time.Duration `yaml:"others-timeout"`
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

	if c.Queue.QueueSize == 0 {
		c.Queue.QueueSize = 65536
	}
	if c.Queue.LabelerQueueCount == 0 {
		c.Queue.LabelerQueueCount = 8
	}
	if c.Queue.FlowGeneratorQueueCount == 0 {
		c.Queue.FlowGeneratorQueueCount = 2
	}
	if c.Queue.MeteringAppQueueCount == 0 {
		c.Queue.MeteringAppQueueCount = 8
	}
	if c.Queue.FlowAppQueueCount == 0 {
		c.Queue.FlowAppQueueCount = 2
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
