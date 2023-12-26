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
	"reflect"
	"regexp"
	"strings"

	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"

	prometheus "github.com/deepflowio/deepflow/server/querier/app/prometheus/config"
	tracing_adapter "github.com/deepflowio/deepflow/server/querier/app/tracing-adapter/config"
	profile "github.com/deepflowio/deepflow/server/querier/profile/config"
)

var log = logging.MustGetLogger("clickhouse")
var Cfg *QuerierConfig
var TraceConfig *TraceIdWithIndex

type Config struct {
	QuerierConfig    QuerierConfig    `yaml:"querier"`
	TraceIdWithIndex TraceIdWithIndex `yaml:"trace-id-with-index"`
}

type QuerierConfig struct {
	LogFile                         string                        `default:"/var/log/querier.log" yaml:"log-file"`
	LogLevel                        string                        `default:"info" yaml:"log-level"`
	ListenPort                      int                           `default:"20416" yaml:"listen-port"`
	Clickhouse                      Clickhouse                    `yaml:clickhouse`
	Profile                         profile.ProfileConfig         `yaml:profile`
	DeepflowApp                     DeepflowApp                   `yaml:"deepflow-app"`
	Prometheus                      prometheus.Prometheus         `yaml:"prometheus"`
	ExternalAPM                     []tracing_adapter.ExternalAPM `yaml:"external-apm"`
	Language                        string                        `default:"en" yaml:"language"`
	OtelEndpoint                    string                        `default:"http://deepflow-agent/api/v1/otel/trace" yaml:"otel-endpoint"`
	Limit                           string                        `default:"10000" yaml:"limit"`
	TimeFillLimit                   int                           `default:"20" yaml:"time-fill-limit"`
	PrometheusCacheUpdateInterval   int                           `default:"60" yaml:"prometheus-cache-update-interval"`
	MaxCacheableEntrySize           int                           `default:"1000" yaml:"max-cacheable-entry-size"`
	MaxPrometheusIdSubqueryLruEntry int                           `default:"8000" yaml:"max-prometheus-id-subquery-lru-entry"`
	PrometheusIdSubqueryLruTimeout  int                           `default:"60" yaml:"prometheus-id-subquery-lru-timeout"`
	AutoCustomTags                  []AutoCustomTags              `yaml:"auto-custom-tags" binding:"omitempty,dive"`
}

type DeepflowApp struct {
	Host string `default:"deepflow-app" yaml:"host"`
	Port string `default:"20418" yaml:"port"`
}

type Location struct {
	Start  int    `yaml:"start"`
	Length int    `yaml:"length"`
	Format string `yaml:"format"`
}

type TraceIdWithIndex struct {
	Enabled               bool     `yaml:"enabled"`
	Type                  string   `yaml:"type"`
	IncrementalIdLocation Location `yaml:"incremental-id-location"`
}

type Clickhouse struct {
	User           string `default:"default" yaml:"user-name"`
	Password       string `default:"" yaml:"user-password"`
	Host           string `default:"clickhouse" yaml:"host"`
	Port           int    `default:"9000" yaml:"port"`
	Timeout        int    `default:"60" yaml:"timeout"`
	ConnectTimeout int    `default:"2" yaml:"connect-timeout"`
	MaxConnection  int    `default:"20" yaml:"max-connection"`
}
type AutoCustomTags struct {
	TagName     string   `default:"" yaml:"tag-name"`
	TagFields   []string `yaml:"tag-fields" binding:"omitempty,dive"`
	DisplayName string   `default:"" yaml:"display_name"`
	Description string   `default:"" yaml:"description"`
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
