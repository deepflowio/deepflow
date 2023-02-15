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

	"github.com/deepflowio/deepflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("event.config")

const (
	DefaultEventTTL = 30
)

type Config struct {
	Base           *config.Config
	CKWriterConfig config.CKWriterConfig `yaml:"event-ck-writer"`
	TTL            int                   `yaml:"event-ttl"`
}

type EventConfig struct {
	Event Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.TTL <= 0 {
		c.TTL = DefaultEventTTL
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &EventConfig{
		Event: Config{
			Base:           base,
			CKWriterConfig: config.CKWriterConfig{QueueCount: 1, QueueSize: 50000, BatchSize: 25600, FlushTimeout: 5},
			TTL:            DefaultEventTTL,
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
