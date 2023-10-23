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

	"github.com/deepflowio/deepflow/server/ingester/config"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("profile.config")

type Config struct {
	Base                 *config.Config
	CKWriterConfig       config.CKWriterConfig `yaml:"profile-ck-writer"`
	ProfileTTL           int                   `yaml:"profile-ttl-hour"`
	DecoderQueueCount    int                   `yaml:"profile-decoder-queue-count"`
	DecoderQueueSize     int                   `yaml:"profile-decoder-queue-size"`
	CompressionAlgorithm *string               `yaml:"profile-compression-algorithm"`
}

type ProfileConfig struct {
	Profile Config `yaml:"ingester"`
}

const (
	DefaultProfileTTL        = 72 // hour
	DefaultDecoderQueueCount = 2
	DefaultDecoderQueueSize  = 1 << 14
)

func (c *Config) Validate() error {
	if c.ProfileTTL <= 0 {
		c.ProfileTTL = DefaultProfileTTL
	}

	if c.DecoderQueueCount == 0 {
		c.DecoderQueueCount = DefaultDecoderQueueCount
	}

	if c.DecoderQueueSize == 0 {
		c.DecoderQueueSize = DefaultDecoderQueueSize
	}

	if c.CompressionAlgorithm == nil {
		// when not configure `profile-compression-algorithm`, default value is `zstd`
		// when configure profile-compression-algorithm with '', will not use compression algo
		c.CompressionAlgorithm = new(string)
		*c.CompressionAlgorithm = "zstd"
	}

	return nil
}

func Load(base *config.Config, path string) *Config {
	config := &ProfileConfig{
		Profile: Config{
			Base:              base,
			CKWriterConfig:    config.CKWriterConfig{QueueCount: 1, QueueSize: 100000, BatchSize: 51200, FlushTimeout: 5},
			ProfileTTL:        DefaultProfileTTL,
			DecoderQueueCount: DefaultDecoderQueueCount,
			DecoderQueueSize:  DefaultDecoderQueueSize,
		},
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Info("no config file, use defaults")
		return &config.Profile
	}
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Warning("Read config file error:", err)
		config.Profile.Validate()
		return &config.Profile
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = config.Profile.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return &config.Profile
}
