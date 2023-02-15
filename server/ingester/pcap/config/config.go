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

var log = logging.MustGetLogger("pcap.config")

const (
	DefaultPcapTTL        = 3
	DefaultPcapQueueCount = 2
	DefaultPcapQueueSize  = 10000
)

type Config struct {
	Base           *config.Config
	PcapQueueCount int                   `yaml:"pcap-queue-count"`
	PcapQueueSize  int                   `yaml:"pcap-queue-size"`
	CKWriterConfig config.CKWriterConfig `yaml:"pcap-ck-writer"`
	TTL            int                   `yaml:"pcap-ttl"`
}

type PcapConfig struct {
	Pcap Config `yaml:"ingester"`
}

func (c *Config) Validate() error {
	if c.PcapQueueCount <= 0 {
		c.PcapQueueCount = DefaultPcapQueueCount
	}
	if c.PcapQueueSize <= 0 {
		c.PcapQueueSize = DefaultPcapQueueSize
	}
	if c.TTL <= 0 {
		c.TTL = DefaultPcapTTL
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &PcapConfig{
		Pcap: Config{
			Base:           base,
			PcapQueueCount: DefaultPcapQueueCount,
			PcapQueueSize:  DefaultPcapQueueSize,
			CKWriterConfig: config.CKWriterConfig{QueueCount: 1, QueueSize: 50000, BatchSize: 2048, FlushTimeout: 5},
			TTL:            DefaultPcapTTL,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Pcap
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Pcap.Validate()
		return &config.Pcap
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Pcap.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Pcap
}
