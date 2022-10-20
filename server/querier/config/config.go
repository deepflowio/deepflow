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

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

var log = logging.MustGetLogger("clickhouse")
var Cfg *QuerierConfig

type Config struct {
	QuerierConfig QuerierConfig `yaml:"querier"`
}

type QuerierConfig struct {
	LogFile    string     `default:"/var/log/querier.log" yaml:"log-file"`
	LogLevel   string     `default:"info" yaml:"log-level"`
	ListenPort int        `default:"20416" yaml:"listen-port"`
	Clickhouse Clickhouse `yaml:clickhouse`
	Language   string     `default:"en" yaml:"language"`
}

type Clickhouse struct {
	User           string `default:"default" yaml:"user-name"`
	Password       string `default:"" yaml:"user-password"`
	Host           string `default:"clickhouse" yaml:"host"`
	Port           int    `default:"9000" yaml:"port"`
	Timeout        int    `default:"60" yaml:"timeout"`
	ConnectTimeout int    `default:"2" yaml:"connect-timeout"`
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) Load(path string) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("Read config file error:", err, path)
		os.Exit(1)
	}

	if err = yaml.Unmarshal(configBytes, c); err != nil {
		log.Error("Unmarshal yaml error:", err)
		os.Exit(1)
	}

	if err = c.Validate(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := SetDefault(cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return cfg
}
