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

var log = logging.MustGetLogger("event.config")

const (
	DefaultDecoderQueueCount     = 1
	DefaultDecoderQueueSize      = 10000
	DefaultPerfDecoderQueueCount = 1
	DefaultPerfDecoderQueueSize  = 100000
	DefaultEventTTL              = 720 // hour
	DefaultPerfEventTTL          = 168 // hour
	DefaultAlarmEventTTL         = 720 // hour
)

type Config struct {
	Base                  *config.Config
	CKWriterConfig        config.CKWriterConfig `yaml:"event-ck-writer"`
	DecoderQueueCount     int                   `yaml:"event-decoder-queue-count"`
	DecoderQueueSize      int                   `yaml:"event-decoder-queue-size"`
	EventTTL              int                   `yaml:"event-ttl"`
	PerfCKWriterConfig    config.CKWriterConfig `yaml:"perf-event-ck-writer"`
	PerfDecoderQueueCount int                   `yaml:"perf-event-decoder-queue-count"`
	PerfDecoderQueueSize  int                   `yaml:"perf-event-decoder-queue-size"`
	PerfEventTTL          int                   `yaml:"perf-event-ttl"`
	AlarmEventTTL         int                   `yaml:"alarm-event-ttl"`
	K8sCKWriterConfig     config.CKWriterConfig `yaml:"k8s-event-ck-writer"`
	K8sDecoderQueueCount  int                   `yaml:"k8s-event-decoder-queue-count"`
	K8sDecoderQueueSize   int                   `yaml:"k8s-event-decoder-queue-size"`
}

type EventConfig struct {
	Event Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}
	if c.DecoderQueueSize == 0 {
		c.DecoderQueueSize = DefaultDecoderQueueSize
	}
	if c.EventTTL <= 0 {
		c.EventTTL = DefaultEventTTL
	}
	if c.PerfDecoderQueueCount == 0 {
		c.PerfDecoderQueueCount = DefaultPerfDecoderQueueCount
	}
	if c.PerfDecoderQueueSize == 0 {
		c.PerfDecoderQueueSize = DefaultPerfDecoderQueueSize
	}
	if c.PerfEventTTL <= 0 {
		c.PerfEventTTL = DefaultPerfEventTTL
	}
	if c.AlarmEventTTL <= 0 {
		c.AlarmEventTTL = DefaultAlarmEventTTL
	}
	if c.K8sDecoderQueueCount == 0 {
		c.K8sDecoderQueueCount = DefaultDecoderQueueCount
	}
	if c.K8sDecoderQueueSize == 0 {
		c.K8sDecoderQueueSize = DefaultDecoderQueueSize
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &EventConfig{
		Event: Config{
			Base:              base,
			CKWriterConfig:    config.CKWriterConfig{QueueCount: 1, QueueSize: 50000, BatchSize: 25600, FlushTimeout: 5},
			DecoderQueueCount: DefaultDecoderQueueCount,
			DecoderQueueSize:  DefaultDecoderQueueSize,
			EventTTL:          DefaultEventTTL,

			PerfCKWriterConfig:    config.CKWriterConfig{QueueCount: 1, QueueSize: 50000, BatchSize: 25600, FlushTimeout: 5},
			PerfDecoderQueueCount: DefaultPerfDecoderQueueCount,
			PerfDecoderQueueSize:  DefaultPerfDecoderQueueSize,
			PerfEventTTL:          DefaultPerfEventTTL,
			AlarmEventTTL:         DefaultAlarmEventTTL,
			K8sCKWriterConfig:     config.CKWriterConfig{QueueCount: 1, QueueSize: 50000, BatchSize: 25600, FlushTimeout: 5},
			K8sDecoderQueueCount:  DefaultDecoderQueueCount,
			K8sDecoderQueueSize:   DefaultDecoderQueueSize,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Event
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Event.Validate()
		return &config.Event
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Event.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Event
}
