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
	"fmt"
	"os"

	cconfig "github.com/deepflowio/deepflow/server/controller/config"
	"github.com/deepflowio/deepflow/server/querier/config"
	"gopkg.in/yaml.v2"
)

var MConfig *MCPConfig

type MCPConfig struct {
	ListenPort      int `default:"20080" yaml:"listen-port"`
	QuerierPort     int
	QuerierLanguage string
}

type Config struct {
	MCPConfig     MCPConfig            `yaml:"mcp"`
	QuerierConfig config.QuerierConfig `yaml:"querier"`
}

func (c *Config) Load(path string) {
	configBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Read config file error: %v, %v\n", err, path)
		os.Exit(1)
	}

	if err = yaml.Unmarshal(configBytes, c); err != nil {
		fmt.Printf("Unmarshal yaml error: %v\n", err)
		os.Exit(1)
	}

	c.MCPConfig.QuerierPort = c.QuerierConfig.ListenPort
	c.MCPConfig.QuerierLanguage = c.QuerierConfig.Language

	MConfig = &c.MCPConfig
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := cconfig.SetDefault(cfg); err != nil {
		fmt.Printf("Set default config error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}
