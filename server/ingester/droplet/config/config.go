/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

const (
	DefaultESHostPort      = "elasticsearch:20042"
	DefaultSyslogDirectory = "/var/log/deepflow-agent"
)

type ESAuth struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type Config struct {
	Base            *config.Config
	ESHostPorts     []string      `yaml:"es-host-port"`
	ESAuth          ESAuth        `yaml:"es-auth"`
	Adapter         AdapterConfig `yaml:"adapter"`
	Labeler         LabelerConfig `yaml:"labeler"`
	Queue           QueueConfig   `yaml:"queue"`
	RpcTimeout      time.Duration `yaml:"rpc-timeout"`
	PCap            PCapConfig    `yaml:"pcap"`
	AgentLogToFile  bool          `yaml:"agent-log-to-file"`
	SyslogDirectory string        `yaml:"syslog-directory"`
	ESSyslog        bool          `yaml:"es-syslog"`
}

type DropletConfig struct {
	Droplet Config `yaml:"ingester"`
}

type AdapterConfig struct {
	OrderingCacheSize uint32 `yaml:"ordering-cache-size"`
}

type LabelerConfig struct {
	FastPathDisable bool   `yaml:"fast-path-disable"`
	MapSizeLimit    uint32 `yaml:"map-size-limit"`
	Level           int    `yaml:"level"`
}

type QueueConfig struct {
	PacketQueueCount    int `yaml:"packet-queue-count"`
	PacketQueueSize     int `yaml:"packet-queue-size"`
	SyslogQueueSize     int `yaml:"syslog-queue-size"`
	StatsdQueueSize     int `yaml:"statsd-queue-size"`
	CompressedQueueSize int `yaml:"compressed-queue-size"`
}

type PCapConfig struct {
	TCPIPChecksum         bool   `yaml:"tcpip-checksum"`
	BlockSizeKB           int    `yaml:"block-size-kb"`
	MaxConcurrentFiles    int    `yaml:"max-concurrent-files"`
	MaxFileSizeMB         int    `yaml:"max-file-size-mb"`
	MaxFilePeriodSecond   int    `yaml:"max-file-period-second"`
	MaxDirectorySizeGB    int    `yaml:"max-directory-size-gb"`
	DiskFreeSpaceMarginGB int    `yaml:"disk-free-space-margin-gb"`
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
	if c.Adapter.OrderingCacheSize < 64 {
		c.Adapter.OrderingCacheSize = 64
	} else if c.Adapter.OrderingCacheSize > 1024 {
		c.Adapter.OrderingCacheSize = 1024
	}

	if c.Labeler.MapSizeLimit == 0 {
		c.Labeler.MapSizeLimit = 1024 * 1024
	}
	if c.Labeler.Level < 1 || c.Labeler.Level > 16 {
		c.Labeler.Level = 8
	}

	if c.Queue.PacketQueueCount < 1 || c.Queue.PacketQueueCount > 16 {
		c.Queue.PacketQueueCount = 1
	} else {
		c.Queue.PacketQueueCount = minPowerOfTwo(c.Queue.PacketQueueCount)
	}
	if c.Queue.PacketQueueSize < 1<<16 {
		c.Queue.PacketQueueSize = 1 << 16
	}
	if c.Queue.SyslogQueueSize < 1<<16 {
		c.Queue.SyslogQueueSize = 1 << 16
	}
	if c.Queue.StatsdQueueSize < 1<<16 {
		c.Queue.StatsdQueueSize = 1 << 16
	}
	if c.Queue.CompressedQueueSize < 1<<16 {
		c.Queue.CompressedQueueSize = 1 << 16
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
	if c.PCap.FileDirectory == "" {
		c.PCap.FileDirectory = common.DEFAULT_PCAP_DATA_PATH
	}

	if c.SyslogDirectory == "" {
		c.SyslogDirectory = DefaultSyslogDirectory
	}
	return nil
}

func Load(base *config.Config, path string) *Config {
	configBytes, err := ioutil.ReadFile(path)
	config := &DropletConfig{
		Droplet: Config{
			Base:        base,
			ESHostPorts: []string{DefaultESHostPort},
			RpcTimeout:  8,
			ESSyslog:    true,
		},
	}
	if err != nil {
		log.Warningf("Read config file error:", err)
		config.Droplet.Validate()
		return &config.Droplet
	}
	if err = yaml.Unmarshal(configBytes, config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Droplet.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Droplet
}
