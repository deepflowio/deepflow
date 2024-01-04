/*
 * Copyright (c) 2024 Yunshan Networks
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

	"github.com/deepflowio/deepflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("ext_metrics.config")

const (
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 1 << 17
	DefaultExtMetricsTTL     = 168 // hour
)

type Config struct {
	Base              *config.Config
	CKWriterConfig    config.CKWriterConfig `yaml:"ext-metrics-ck-writer"`
	DecoderQueueCount int                   `yaml:"ext-metrics-decoder-queue-count"`
	DecoderQueueSize  int                   `yaml:"ext-metrics-decoder-queue-size"`
	TTL               int                   `yaml:"ext-metrics-ttl-hour"`
}

type ExtMetricsConfig struct {
	ExtMetrics Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}
	if c.TTL <= 0 {
		c.TTL = DefaultExtMetricsTTL
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &ExtMetricsConfig{
		ExtMetrics: Config{
			Base:              base,
			DecoderQueueCount: DefaultDecoderQueueCount,
			DecoderQueueSize:  DefaultDecoderQueueSize,
			CKWriterConfig:    config.CKWriterConfig{QueueCount: 1, QueueSize: 100000, BatchSize: 51200, FlushTimeout: 10},
			TTL:               DefaultExtMetricsTTL,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.ExtMetrics
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.ExtMetrics.Validate()
		return &config.ExtMetrics
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.ExtMetrics.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.ExtMetrics
}
