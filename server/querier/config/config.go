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
	"reflect"
	"regexp"

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
	"strings"
)

var log = logging.MustGetLogger("clickhouse")
var Cfg *QuerierConfig

type Config struct {
	QuerierConfig QuerierConfig `yaml:"querier"`
}

type QuerierConfig struct {
	LogFile       string      `default:"/var/log/querier.log" yaml:"log-file"`
	LogLevel      string      `default:"info" yaml:"log-level"`
	ListenPort    int         `default:"20416" yaml:"listen-port"`
	Clickhouse    Clickhouse  `yaml:clickhouse`
	DeepflowApp   DeepflowApp `yaml:"deepflow-app"`
	Prometheus    Prometheus  `yaml:"prometheus"`
	Language      string      `default:"en" yaml:"language"`
	OtelEndpoint  string      `default:"http://${K8S_NODE_IP_FOR_DEEPFLOW}:38086/api/v1/otel/trace" yaml:"otel-endpoint"`
	Limit         string      `default:"10000" yaml:"limit"`
	TimeFillLimit int         `default:"20" yaml:"time-fill-limit"`
}

type DeepflowApp struct {
	Host string `default:"deepflow-app" yaml:"host"`
	Port string `default:"20418" yaml:"port"`
}

type Clickhouse struct {
	User           string `default:"default" yaml:"user-name"`
	Password       string `default:"" yaml:"user-password"`
	Host           string `default:"clickhouse" yaml:"host"`
	Port           int    `default:"9000" yaml:"port"`
	Timeout        int    `default:"60" yaml:"timeout"`
	ConnectTimeout int    `default:"2" yaml:"connect-timeout"`
}

type Prometheus struct {
	SeriesLimit int `default:"100" yaml:"series-limit"`
}

func (c *Config) expendEnv() {
	reConfig := reflect.ValueOf(&c.QuerierConfig)
	reConfig = reConfig.Elem()
	for i := 0; i < reConfig.NumField(); i++ {
		field := reConfig.Field(i)
		switch field.Type().String() {
		case "string":
			fieldStr := field.String()
			pattern := regexp.MustCompile(`\$\{(.+?)\}`)
			p := pattern.FindAllSubmatch([]byte(fieldStr), -1)
			for _, i := range p {
				str := string(i[1])
				fieldStr = strings.Replace(fieldStr, string(i[0]), os.Getenv(str), 1)
			}
			field.SetString(fieldStr)
		}
	}
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
	c.expendEnv()
}

func DefaultConfig() *Config {
	cfg := &Config{}
	if err := SetDefault(cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	return cfg
}
