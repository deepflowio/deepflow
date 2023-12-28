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

var log = logging.MustGetLogger("prometheus.config")

const (
	DefaultDecoderQueueCount            = 1
	DefaultDecoderQueueSize             = 1 << 14
	DefaultPrometheusTTL                = 168       // hour
	DefaultLabelMsgMaxSize              = 100 << 20 // 100M
	DefaultLabelRequestMetricBatchCount = 128
	DefaultAppLabelColumnIncrement      = 4
	DefaultAppLabelColumnMinCount       = 8
	DefaultLabelCacheExpiration         = 86400 // 1 day
)

type Config struct {
	Base                         *config.Config
	CKWriterConfig               config.CKWriterConfig `yaml:"prometheus-ck-writer"`
	DecoderQueueCount            int                   `yaml:"prometheus-decoder-queue-count"`
	DecoderQueueSize             int                   `yaml:"prometheus-decoder-queue-size"`
	TTL                          int                   `yaml:"prometheus-ttl-hour"`
	LabelMsgMaxSize              int                   `yaml:"prometheus-label-msg-max-size"`
	LabelRequestMetricBatchCount int                   `yaml:"prometheus-label-request-metric-batch-count"`
	AppLabelColumnIncrement      int                   `yaml:"prometheus-app-label-column-increment"`
	AppLabelColumnMinCount       int                   `yaml:"prometheus-app-label-column-min-count"`
	IgnoreUniversalTag           bool                  `yaml:"prometheus-sample-ignore-universal-tag"`
	LabelCacheExpiration         int                   `yaml:"prometheus-label-cache-expiration"`
}

type PrometheusConfig struct {
	Prometheus Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}
	if c.TTL <= 0 {
		c.TTL = DefaultPrometheusTTL
	}
	if c.LabelMsgMaxSize <= 0 {
		c.LabelMsgMaxSize = DefaultLabelMsgMaxSize
	}
	if c.LabelRequestMetricBatchCount <= 0 {
		c.LabelRequestMetricBatchCount = DefaultLabelRequestMetricBatchCount
	}
	if c.AppLabelColumnIncrement <= 0 {
		c.AppLabelColumnIncrement = DefaultAppLabelColumnIncrement
	}
	if c.AppLabelColumnMinCount <= 0 {
		c.AppLabelColumnMinCount = DefaultAppLabelColumnMinCount
	}
	if c.LabelCacheExpiration <= 0 {
		c.LabelCacheExpiration = DefaultLabelCacheExpiration
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &PrometheusConfig{
		Prometheus: Config{
			Base:                         base,
			DecoderQueueCount:            DefaultDecoderQueueCount,
			DecoderQueueSize:             DefaultDecoderQueueSize,
			CKWriterConfig:               config.CKWriterConfig{QueueCount: 1, QueueSize: 524288, BatchSize: 262144, FlushTimeout: 10},
			TTL:                          DefaultPrometheusTTL,
			LabelMsgMaxSize:              DefaultLabelMsgMaxSize,
			LabelRequestMetricBatchCount: DefaultLabelRequestMetricBatchCount,
			AppLabelColumnIncrement:      DefaultAppLabelColumnIncrement,
			AppLabelColumnMinCount:       DefaultAppLabelColumnMinCount,
			LabelCacheExpiration:         DefaultLabelCacheExpiration,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Prometheus
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Prometheus.Validate()
		return &config.Prometheus
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Prometheus.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Prometheus
}
