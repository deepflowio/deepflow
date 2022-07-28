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

	"github.com/deepflowys/deepflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("stream.config")

const (
	DefaultThrottle          = 50000
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 10000
	DefaultBrokerQueueSize   = 10000
)

type FlowLogDisabled struct {
	L4    bool `yaml:"l4"`
	L7    bool `yaml:"l7"`
	Http  bool `yaml:"http"`
	Dns   bool `yaml:"dns"`
	Mysql bool `yaml:"mysql"`
	Redis bool `yaml:"redis"`
	Dubbo bool `yaml:"dubbo"`
	Kafka bool `yaml:"kafka"`
	Mqtt  bool `yaml:"mqtt"`
}

type Config struct {
	Base              *config.Config
	ReplicaEnabled    bool                  `yaml:"flowlog-replica-enabled"`
	CKWriterConfig    config.CKWriterConfig `yaml:"flowlog-ck-writer"`
	Throttle          int                   `yaml:"throttle"`
	L4Throttle        int                   `yaml:"l4-throttle"`
	L7Throttle        int                   `yaml:"l7-throttle"`
	FlowLogDisabled   FlowLogDisabled       `yaml:"flow-log-disabled"`
	DecoderQueueCount int                   `yaml:"decoder-queue-count"`
	DecoderQueueSize  int                   `yaml:"decoder-queue-size"`
}
type StreamConfig struct {
	Stream Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &StreamConfig{
		Stream: Config{
			Base:              base,
			Throttle:          DefaultThrottle,
			DecoderQueueCount: DefaultDecoderQueueCount,
			DecoderQueueSize:  DefaultDecoderQueueSize,
			CKWriterConfig:    config.CKWriterConfig{QueueCount: 1, QueueSize: 1000000, BatchSize: 512000, FlushTimeout: 10},
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Stream
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Stream.Validate()
		return &config.Stream
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Stream.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Stream
}
