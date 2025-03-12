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
	"os"

	"github.com/deepflowio/deepflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("event.config")

const (
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 4096
	DefaultTTL               = 720 // hour
)

type Config struct {
	Base              *config.Config
	CKWriterConfig    config.CKWriterConfig `yaml:"application-log-ck-writer"`
	DecoderQueueCount int                   `yaml:"application-log-decoder-queue-count"`
	DecoderQueueSize  int                   `yaml:"application-log-decoder-queue-size"`
	TTL               int                   `yaml:"application-log-ttl-hour"`
}

type ApplicationLogConfig struct {
	ApplicationLog Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}
	if c.DecoderQueueSize == 0 {
		c.DecoderQueueSize = DefaultDecoderQueueSize
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &ApplicationLogConfig{
		ApplicationLog: Config{
			Base:              base,
			CKWriterConfig:    config.CKWriterConfig{QueueCount: 2, QueueSize: 25600, BatchSize: 12800, FlushTimeout: 5},
			DecoderQueueCount: DefaultDecoderQueueCount,
			DecoderQueueSize:  DefaultDecoderQueueSize,
			TTL:               DefaultTTL,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.ApplicationLog
	}
	configBytes, err := os.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.ApplicationLog.Validate()
		return &config.ApplicationLog
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.ApplicationLog.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.ApplicationLog
}
