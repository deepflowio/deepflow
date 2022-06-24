package config

import (
	"errors"
	"io/ioutil"
	"net"
	"os"
	"strings"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

const (
	DefaultCheckInterval   = 600 // clickhouse是异步删除
	DefaultDiskUsedPercent = 90
	DefaultDiskFreeSpace   = 50
	DefaultCKDBS3Volume    = "vol_s3"
	DefaultCKDBS3TTLTimes  = 3 // 对象存储的保留时长是本地存储的3倍
	DefaultInfluxdbHost    = "influxdb"
	DefaultInfluxdbPort    = "20044"
)

type CKDiskMonitor struct {
	CheckInterval int `yaml:"check-interval"` // s
	UsedPercent   int `yaml:"used-percent"`   // 0-100
	FreeSpace     int `yaml:"free-space"`     // Gb
}

type CKS3Storage struct {
	Enabled  bool   `yaml:"enabled"`
	Volume   string `yaml:"volume"`
	TTLTimes int    `yaml:"ttl-times"`
}

type HostPort struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}

type Config struct {
	ControllerIps     []string      `yaml:"controller-ips,flow"`
	ControllerPort    uint16        `yaml:"controller-port"`
	StreamRozeEnabled bool          `yaml:"stream-roze-enabled"`
	UDPReadBuffer     int           `yaml:"udp-read-buffer"`
	TCPReadBuffer     int           `yaml:"tcp-read-buffer"`
	LogFile           string        `yaml:"log-file"`
	LogLevel          string        `yaml:"log-level"`
	Profiler          bool          `yaml:"profiler"`
	MaxCPUs           int           `yaml:"max-cpus"`
	CKDiskMonitor     CKDiskMonitor `yaml:"ck-disk-monitor"`
	CKS3Storage       CKS3Storage   `yaml:"ckdb-s3"`
	Influxdb          HostPort      `yaml:"influxdb"`
}

type BaseConfig struct {
	Base Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if len(c.ControllerIps) == 0 {
		log.Warning("controller-ips is empty")
	} else {
		for _, ipString := range c.ControllerIps {
			if net.ParseIP(ipString) == nil {
				return errors.New("controller-ips invalid")
			}
		}
	}

	level := strings.ToLower(c.LogLevel)
	c.LogLevel = "info"
	for _, l := range []string{"error", "warn", "info", "debug"} {
		if level == l {
			c.LogLevel = l
		}
	}

	return nil
}

func Load(path string) Config {
	configBytes, err := ioutil.ReadFile(path)
	config := BaseConfig{
		Base: Config{
			ControllerPort: 20035,
			UDPReadBuffer:  64 << 20,
			TCPReadBuffer:  4 << 20,
			LogFile:        "/var/log/ingester/ingester.log",
			CKDiskMonitor:  CKDiskMonitor{DefaultCheckInterval, DefaultDiskUsedPercent, DefaultDiskFreeSpace},
			CKS3Storage:    CKS3Storage{false, DefaultCKDBS3Volume, DefaultCKDBS3TTLTimes},
			Influxdb:       HostPort{DefaultInfluxdbHost, DefaultInfluxdbPort},
		},
	}
	if err != nil {
		log.Error("Read config file error:", err)
		os.Exit(1)
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Base.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return config.Base
}
