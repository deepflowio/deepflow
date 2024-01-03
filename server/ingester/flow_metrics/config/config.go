/*
 * Copyright (c) 2023 Yunshan Networks
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

	"github.com/deepflowio/deepflow/server/ingester/common"
	"github.com/deepflowio/deepflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

const (
	DefaultUnmarshallQueueCount   = 4
	DefaultUnmarshallQueueSize    = 10240
	DefaultReceiverWindowSize     = 1024
	DefaultCKReadTimeout          = 300
	DefaultFlowMetrics1MTTL       = 168 // hour
	DefaultFlowMetrics1STTL       = 24  // hour
	DefaultPromWriterQueueCount   = 2
	DefaultPromWriterQueueSize    = 100000
	DefaultPromWriterBatchSize    = 2048
	DefaultPromWriterFlushTimeout = 5
)

type PCapConfig struct {
	FileDirectory string `yaml:"file-directory"`
}

type FlowMetricsTTL struct {
	VtapFlow1M int `yaml:"vtap-flow-1m"`
	VtapFlow1S int `yaml:"vtap-flow-1s"`
	VtapApp1M  int `yaml:"vtap-app-1m"`
	VtapApp1S  int `yaml:"vtap-app-1s"`
}

type PromWriterConfig struct {
	Enabled       bool              `yaml:"enabled"`
	Endpoint      string            `yaml:"endpoint"`
	Headers       map[string]string `yaml:"headers"`
	BatchSize     int               `yaml:"batch-size"`
	FlushTimeout  int               `yaml:"flush-timeout"`
	QueueCount    int               `yaml:"queue-count"`
	QueueSize     int               `yaml:"queue-size"`
	MetricsFilter []string          `yaml:"metrics-filter"`
}

type Config struct {
	Base                 *config.Config
	CKReadTimeout        int                   `yaml:"ck-read-timeout"`
	CKWriterConfig       config.CKWriterConfig `yaml:"metrics-ck-writer"`
	PromWriterConfig     PromWriterConfig      `yaml:"metrics-prom-writer"`
	Pcap                 PCapConfig            `yaml:"pcap"`
	DisableSecondWrite   bool                  `yaml:"disable-second-write"`
	UnmarshallQueueCount int                   `yaml:"unmarshall-queue-count"`
	UnmarshallQueueSize  int                   `yaml:"unmarshall-queue-size"`
	ReceiverWindowSize   uint64                `yaml:"receiver-window-size"`
	FlowMetricsTTL       FlowMetricsTTL        `yaml:"flow-metrics-ttl-hour"`
}

type FlowMetricsConfig struct {
	FlowMetrics Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.ReceiverWindowSize < 64 || c.ReceiverWindowSize > 64*1024 {
		c.ReceiverWindowSize = DefaultReceiverWindowSize
	}

	if c.FlowMetricsTTL.VtapFlow1M == 0 {
		c.FlowMetricsTTL.VtapFlow1M = DefaultFlowMetrics1MTTL
	}

	if c.FlowMetricsTTL.VtapFlow1S == 0 {
		c.FlowMetricsTTL.VtapFlow1S = DefaultFlowMetrics1STTL
	}

	if c.FlowMetricsTTL.VtapApp1M == 0 {
		c.FlowMetricsTTL.VtapApp1M = DefaultFlowMetrics1MTTL
	}

	if c.FlowMetricsTTL.VtapApp1S == 0 {
		c.FlowMetricsTTL.VtapApp1S = DefaultFlowMetrics1STTL
	}

	if c.PromWriterConfig.QueueCount <= 0 {
		c.PromWriterConfig.QueueCount = DefaultPromWriterQueueCount
	}
	if c.PromWriterConfig.QueueSize <= 0 {
		c.PromWriterConfig.QueueCount = DefaultPromWriterQueueSize
	}

	if c.PromWriterConfig.BatchSize <= 0 {
		c.PromWriterConfig.BatchSize = DefaultPromWriterBatchSize
	}

	if c.PromWriterConfig.FlushTimeout <= 0 {
		c.PromWriterConfig.FlushTimeout = DefaultPromWriterFlushTimeout
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &FlowMetricsConfig{
		FlowMetrics: Config{
			Base:                 base,
			CKWriterConfig:       config.CKWriterConfig{QueueCount: 1, QueueSize: 1000000, BatchSize: 512000, FlushTimeout: 10},
			PromWriterConfig:     PromWriterConfig{},
			CKReadTimeout:        DefaultCKReadTimeout,
			UnmarshallQueueCount: DefaultUnmarshallQueueCount,
			UnmarshallQueueSize:  DefaultUnmarshallQueueSize,
			ReceiverWindowSize:   DefaultReceiverWindowSize,
			FlowMetricsTTL:       FlowMetricsTTL{DefaultFlowMetrics1MTTL, DefaultFlowMetrics1STTL, DefaultFlowMetrics1MTTL, DefaultFlowMetrics1STTL},

			Pcap: PCapConfig{common.DEFAULT_PCAP_DATA_PATH},
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.FlowMetrics
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warningf("Read config file error:", err)
		config.FlowMetrics.Validate()
		return &config.FlowMetrics
	}
	if err = yaml.Unmarshal(configBytes, config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.FlowMetrics.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	return &config.FlowMetrics
}
