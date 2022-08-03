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

	"github.com/deepflowys/deepflow/server/ingester/common"
	"github.com/deepflowys/deepflow/server/ingester/config"

	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("config")

const (
	DefaultUnmarshallQueueCount = 4
	DefaultUnmarshallQueueSize  = 10240
	DefaultReceiverWindowSize   = 1024
	DefaultCKReadTimeout        = 300
)

type PCapConfig struct {
	FileDirectory string `yaml:"file-directory"`
}

type Config struct {
	Base                      *config.Config
	CKReadTimeout             int                   `yaml:"ck-read-timeout"`
	ReplicaEnabled            bool                  `yaml:"metrics-replica-enabled"`
	CKWriterConfig            config.CKWriterConfig `yaml:"metrics-ck-writer"`
	Pcap                      PCapConfig            `yaml:"pcap"`
	DisableSecondWrite        bool                  `yaml:"disable-second-write"`
	DisableSecondWriteReplica bool                  `yaml:"disable-second-write-replica"`
	UnmarshallQueueCount      int                   `yaml:"unmarshall-queue-count"`
	UnmarshallQueueSize       int                   `yaml:"unmarshall-queue-size"`
	ReceiverWindowSize        uint64                `yaml:"receiver-window-size"`
}

type RozeConfig struct {
	Roze Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.ReceiverWindowSize < 64 || c.ReceiverWindowSize > 64*1024 {
		c.ReceiverWindowSize = DefaultReceiverWindowSize
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &RozeConfig{
		Roze: Config{
			Base:                      base,
			CKWriterConfig:            config.CKWriterConfig{QueueCount: 1, QueueSize: 1000000, BatchSize: 512000, FlushTimeout: 10},
			CKReadTimeout:             DefaultCKReadTimeout,
			UnmarshallQueueCount:      DefaultUnmarshallQueueCount,
			UnmarshallQueueSize:       DefaultUnmarshallQueueSize,
			ReceiverWindowSize:        DefaultReceiverWindowSize,
			DisableSecondWriteReplica: true,

			Pcap: PCapConfig{common.DEFAULT_PCAP_DATA_PATH},
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Roze
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warningf("Read config file error:", err)
		config.Roze.Validate()
		return &config.Roze
	}
	if err = yaml.Unmarshal(configBytes, config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Roze.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	return &config.Roze
}
